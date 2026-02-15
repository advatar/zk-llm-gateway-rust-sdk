use crate::crypto::{open_json, seal_json, Envelope, GatewayPublicKey};
use crate::error::{Error, Result};
use crate::openai::{ChatCompletionsRequest, ChatCompletionsResponse};
use crate::ticket::{TicketSource, ZkTicket};
use crate::token_class::TokenClass;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT};
use std::sync::Arc;
use url::Url;

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
            .field("token", &self.config.auth_bearer.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl GatewayClient {
    /// Create a new client with default configuration.
    pub fn new(endpoint: Url, gateway_pk: GatewayPublicKey, tickets: Arc<dyn TicketSource>) -> Self {
        let config = GatewayClientConfig::default();
        Self::with_config(endpoint, gateway_pk, tickets, config)
            .expect("valid infer url")
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

    /// Generic inference call. `upstream` can be any JSON payload the gateway/proxy understands.
    pub async fn infer_json(&self, token_class: TokenClass, upstream: serde_json::Value) -> Result<serde_json::Value> {
        let ticket = self.tickets.next_ticket(token_class).await?;
        self.infer_json_with_ticket(token_class, ticket, upstream).await
    }

    /// Same as `infer_json`, but the caller supplies the ticket.
    pub async fn infer_json_with_ticket(
        &self,
        token_class: TokenClass,
        ticket: ZkTicket,
        upstream: serde_json::Value,
    ) -> Result<serde_json::Value> {
        // Plaintext payload (will be padded and encrypted)
        let payload = serde_json::json!({
            "token_class": token_class,
            "ticket": ticket,
            "upstream": upstream,
        });

        let (env, st) = seal_json(&self.gateway_pk, token_class, &payload)?;

        let mut req = self.http.post(self.infer_url.clone()).json(&env);
        if let Some(bearer) = &self.config.auth_bearer {
            req = req.bearer_auth(bearer);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let resp_env: Envelope = resp.json().await?;

        // Decrypt, then interpret.
        let decrypted = open_json(&resp_env, &st)?;

        // If gateway returned an encrypted error payload, surface it.
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

        // For non-2xx, still allow encrypted errors to be handled above.
        if !status.is_success() {
            return Err(Error::GatewayError {
                code: "http_error".to_string(),
                message: format!("gateway returned HTTP {}", status),
            });
        }

        decrypted
            .get("upstream")
            .cloned()
            .ok_or_else(|| Error::Protocol("missing 'upstream' field in decrypted gateway response".to_string()))
    }

    /// Convenience: OpenAI-style Chat Completions.
    pub async fn chat_completions(
        &self,
        token_class: TokenClass,
        mut req: ChatCompletionsRequest,
    ) -> Result<ChatCompletionsResponse> {
        // Encourage consistent max_tokens (gateway may override anyway).
        if req.max_tokens.is_none() {
            req.max_tokens = Some(token_class.max_output_tokens_hint());
        }

        let upstream = serde_json::to_value(req)?;
        let resp_json = self
            .infer_json(token_class, serde_json::json!({
                "path": "/v1/chat/completions",
                "method": "POST",
                "body": upstream,
            }))
            .await?;

        // Expect the gateway to return the upstream JSON response in this structure.
        // If your gateway returns raw OpenAI JSON directly, just deserialize resp_json.
        let body = resp_json
            .get("body")
            .cloned()
            .unwrap_or(resp_json);

        Ok(serde_json::from_value::<ChatCompletionsResponse>(body)?)
    }
}
