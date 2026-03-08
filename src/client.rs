use crate::crypto::{open_json, seal_json, Envelope, GatewayPublicKey};
use crate::error::{Error, Result};
use crate::openai::{ChatChoice, ChatCompletionsRequest, ChatCompletionsResponse, ChatMessage};
use crate::ticket::{TicketSource, ZkTicket};
use crate::token_class::TokenClass;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct GatewayClientConfig {
    /// Path for the encrypted inference endpoint.
    pub infer_path: String,

    /// Optional Authorization bearer token (not recommended for privacy; use tickets where possible).
    pub auth_bearer: Option<String>,

    /// Request timeout in seconds.
    pub timeout_secs: u64,

    /// Additional headers to include.
    pub headers: HeaderMap,
}

impl Default for GatewayClientConfig {
    fn default() -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Self {
            infer_path: "/v1/infer".to_string(),
            auth_bearer: None,
            timeout_secs: 60,
            headers,
        }
    }
}

impl GatewayClientConfig {
    pub fn with_auth_bearer(mut self, bearer: impl Into<String>) -> Self {
        self.auth_bearer = Some(bearer.into());
        self
    }
}

#[derive(Debug, Clone, Serialize)]
struct InferenceRequest {
    request_id: Uuid,
    model: String,
    messages: Vec<ChatMessage>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,

    token_class: TokenClass,
    ticket: ZkTicket,

    #[serde(default, flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InferenceResponse {
    request_id: Uuid,
    model: String,
    output: String,
    billed_token_class: TokenClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upstream: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ErrorResponse {
    code: String,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum GatewayEnvelopePayload {
    Ok { response: InferenceResponse },
    Err { error: ErrorResponse },
}

fn parse_chat_request(upstream: Value) -> Result<ChatCompletionsRequest> {
    let direct = upstream.get("model").is_some() && upstream.get("messages").is_some();
    if direct {
        return serde_json::from_value(upstream)
            .map_err(|e| Error::Protocol(format!("invalid chat request payload: {}", e)));
    }

    let path = upstream.get("path").and_then(|v| v.as_str());
    if path == Some("/v1/chat/completions") {
        let body = upstream
            .get("body")
            .cloned()
            .ok_or_else(|| Error::Protocol("missing 'body' in upstream wrapper".to_string()))?;
        return serde_json::from_value(body)
            .map_err(|e| Error::Protocol(format!("invalid upstream body payload: {}", e)));
    }

    Err(Error::Protocol(
        "unsupported infer_json payload; expected ChatCompletions request or {path, body} wrapper"
            .to_string(),
    ))
}

fn build_inference_request(
    token_class: TokenClass,
    ticket: ZkTicket,
    req: ChatCompletionsRequest,
) -> Result<InferenceRequest> {
    if req.stream == Some(true) {
        return Err(Error::Protocol(
            "stream=true is not supported on /v1/infer".to_string(),
        ));
    }

    let ChatCompletionsRequest {
        model,
        messages,
        temperature,
        max_tokens,
        stream,
        extra,
    } = req;

    let extra = extra
        .into_iter()
        .filter(|(key, _)| !matches!(key.as_str(), "request_id" | "token_class" | "ticket"))
        .collect();

    Ok(InferenceRequest {
        request_id: Uuid::new_v4(),
        model,
        messages,
        max_tokens,
        temperature,
        stream,
        token_class,
        ticket,
        extra,
    })
}

fn parse_chat_completions_response(
    default_model: &str,
    resp_json: Value,
) -> Result<ChatCompletionsResponse> {
    // Preferred: canonical response object.
    if let Ok(ir) = serde_json::from_value::<InferenceResponse>(resp_json.clone()) {
        let billed_token_class = serde_json::to_value(ir.billed_token_class).unwrap_or(Value::Null);

        if let Some(upstream) = ir.upstream.clone() {
            let body = upstream.get("body").cloned().unwrap_or(upstream);
            if let Ok(mut response) = serde_json::from_value::<ChatCompletionsResponse>(body) {
                response
                    .extra
                    .insert("billed_token_class".to_string(), billed_token_class.clone());
                if response.id.is_none() {
                    response.id = Some(ir.request_id.to_string());
                }
                if response.model.is_none() {
                    response.model = Some(ir.model.clone());
                }
                return Ok(response);
            }
        }

        let mut extra = HashMap::new();
        extra.insert("billed_token_class".to_string(), billed_token_class);

        return Ok(ChatCompletionsResponse {
            id: Some(ir.request_id.to_string()),
            model: Some(ir.model.clone()),
            choices: vec![ChatChoice {
                index: 0,
                message: Some(ChatMessage::assistant(ir.output)),
                finish_reason: Some("stop".to_string()),
                extra: HashMap::new(),
            }],
            usage: None,
            extra,
        });
    }

    // Backward-compatible parsing for SDK-proxy gateways.
    let body = resp_json.get("body").cloned().unwrap_or(resp_json);
    let mut response = serde_json::from_value::<ChatCompletionsResponse>(body)?;
    if response.model.is_none() {
        response.model = Some(default_model.to_string());
    }
    Ok(response)
}

#[derive(Clone)]
pub struct GatewayClient {
    endpoint: Url,
    infer_url: Url,
    gateway_pk: GatewayPublicKey,
    tickets: Arc<dyn TicketSource>,
    http: reqwest::Client,
    config: GatewayClientConfig,
}

impl std::fmt::Debug for GatewayClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayClient")
            .field("endpoint", &self.endpoint)
            .field("infer_url", &self.infer_url)
            .field(
                "token",
                &self.config.auth_bearer.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl GatewayClient {
    /// Create a new client with default configuration.
    pub fn new(
        endpoint: Url,
        gateway_pk: GatewayPublicKey,
        tickets: Arc<dyn TicketSource>,
    ) -> Self {
        let config = GatewayClientConfig::default();
        Self::with_config(endpoint, gateway_pk, tickets, config).expect("valid infer url")
    }

    pub fn with_config(
        endpoint: Url,
        gateway_pk: GatewayPublicKey,
        tickets: Arc<dyn TicketSource>,
        config: GatewayClientConfig,
    ) -> Result<Self> {
        let infer_url = endpoint.join(&config.infer_path)?;

        let mut default_headers = config.headers.clone();
        default_headers.insert(
            USER_AGENT,
            HeaderValue::from_static("zk-llm-gateway-sdk/0.1"),
        );

        let http = reqwest::Client::builder()
            .default_headers(default_headers)
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()?;

        Ok(Self {
            endpoint,
            infer_url,
            gateway_pk,
            tickets,
            http,
            config,
        })
    }

    /// Encrypted inference call against the gateway's canonical `InferenceRequest` protocol.
    ///
    /// `upstream` may be either:
    /// - a direct OpenAI-style chat body `{model, messages, ...}`
    /// - a legacy wrapper `{path:"/v1/chat/completions", body:{...}}`
    pub async fn infer_json(&self, token_class: TokenClass, upstream: Value) -> Result<Value> {
        let ticket = self.tickets.next_ticket(token_class).await?;
        self.infer_json_with_ticket(token_class, ticket, upstream)
            .await
    }

    pub async fn infer_json_with_ticket(
        &self,
        token_class: TokenClass,
        ticket: ZkTicket,
        upstream: Value,
    ) -> Result<Value> {
        if ticket.token_class != token_class {
            return Err(Error::Protocol(
                "ticket token_class must match requested token_class".to_string(),
            ));
        }

        let chat_req = parse_chat_request(upstream)?;
        let payload = build_inference_request(token_class, ticket, chat_req)?;

        let payload_json = serde_json::to_value(payload)?;
        let (env, st) = seal_json(&self.gateway_pk, token_class, &payload_json)?;

        let mut req = self.http.post(self.infer_url.clone()).json(&env);
        if let Some(bearer) = &self.config.auth_bearer {
            req = req.bearer_auth(bearer);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let resp_env: Envelope = resp.json().await?;

        let decrypted = open_json(&resp_env, &st)?;

        // Canonical payload.
        if let Ok(payload) = serde_json::from_value::<GatewayEnvelopePayload>(decrypted.clone()) {
            match payload {
                GatewayEnvelopePayload::Ok { response } => {
                    return Ok(serde_json::to_value(response)?);
                }
                GatewayEnvelopePayload::Err { error } => {
                    return Err(Error::GatewayError {
                        code: error.code,
                        message: error.message,
                    });
                }
            }
        }

        // Legacy SDK payload shape for compatibility.
        if let Some(err) = decrypted.get("error") {
            let code = err
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("gateway_error")
                .to_string();
            let message = err
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
                .to_string();
            return Err(Error::GatewayError { code, message });
        }

        if !status.is_success() {
            return Err(Error::GatewayError {
                code: "http_error".to_string(),
                message: format!("gateway returned HTTP {}", status),
            });
        }

        decrypted
            .get("upstream")
            .cloned()
            .or_else(|| decrypted.get("response").cloned())
            .ok_or_else(|| {
                Error::Protocol(
                    "missing response payload in decrypted gateway response".to_string(),
                )
            })
    }

    /// Convenience: OpenAI-style Chat Completions.
    pub async fn chat_completions(
        &self,
        token_class: TokenClass,
        mut req: ChatCompletionsRequest,
    ) -> Result<ChatCompletionsResponse> {
        if req.max_tokens.is_none() {
            req.max_tokens = Some(token_class.max_output_tokens_hint());
        }

        let default_model = req.model.clone();
        let resp_json = self
            .infer_json(token_class, serde_json::to_value(req)?)
            .await?;
        parse_chat_completions_response(&default_model, resp_json)
    }
}

#[cfg(test)]
mod tests {
    use super::{build_inference_request, parse_chat_completions_response};
    use crate::openai::{ChatCompletionsRequest, ChatMessage};
    use crate::ticket::ZkTicket;
    use crate::token_class::TokenClass;
    use serde_json::json;
    use std::collections::HashMap;
    use uuid::Uuid;

    #[test]
    fn build_inference_request_preserves_passthrough_fields() {
        let mut extra = HashMap::new();
        extra.insert("top_p".to_string(), json!(0.9));
        extra.insert(
            "tools".to_string(),
            json!([{ "type": "function", "function": { "name": "lookup" } }]),
        );

        let req = ChatCompletionsRequest {
            model: "gpt-4o-mini".to_string(),
            messages: vec![ChatMessage::user("hello")],
            temperature: Some(0.2),
            max_tokens: Some(128),
            stream: Some(false),
            extra,
        };

        let ticket = ZkTicket::random_dummy(TokenClass::C1024);
        let payload =
            build_inference_request(TokenClass::C1024, ticket.clone(), req).expect("payload");
        let payload_json = serde_json::to_value(payload).expect("serialize payload");

        assert_eq!(payload_json["stream"], json!(false));
        assert_eq!(payload_json["top_p"], json!(0.9));
        assert_eq!(payload_json["tools"][0]["function"]["name"], json!("lookup"));
        assert_eq!(payload_json["token_class"], json!("c1024"));
        assert_eq!(payload_json["ticket"]["nullifier"], json!(ticket.nullifier));
    }

    #[test]
    fn build_inference_request_rejects_stream_true() {
        let req = ChatCompletionsRequest {
            model: "gpt-4o-mini".to_string(),
            messages: vec![ChatMessage::user("hello")],
            temperature: None,
            max_tokens: None,
            stream: Some(true),
            extra: HashMap::new(),
        };

        let err = build_inference_request(
            TokenClass::C512,
            ZkTicket::random_dummy(TokenClass::C512),
            req,
        )
        .expect_err("stream=true should fail");

        assert!(err.to_string().contains("stream=true is not supported"));
    }

    #[test]
    fn canonical_response_prefers_raw_upstream_body() {
        let request_id = Uuid::new_v4();
        let resp_json = json!({
            "request_id": request_id,
            "model": "gpt-4o-mini",
            "output": "",
            "billed_token_class": "c2048",
            "upstream": {
                "id": "chatcmpl-123",
                "model": "gpt-4o-mini",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "lookup_weather",
                                "arguments": "{\"city\":\"Stockholm\"}"
                            }
                        }]
                    },
                    "finish_reason": "tool_calls"
                }]
            }
        });

        let response =
            parse_chat_completions_response("fallback-model", resp_json).expect("parse response");

        assert_eq!(response.id.as_deref(), Some("chatcmpl-123"));
        assert_eq!(
            response.extra.get("billed_token_class"),
            Some(&json!("c2048"))
        );
        let message = response.choices[0].message.as_ref().expect("assistant message");
        assert_eq!(message.content, "");
        assert_eq!(
            message.extra["tool_calls"][0]["function"]["name"],
            json!("lookup_weather")
        );
    }
}
