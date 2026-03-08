use crate::client::{GatewayClient, GatewayClientConfig};
use crate::crypto::GatewayPublicKey;
use crate::error::{Error, Result};
use crate::openai::{ChatCompletionsRequest, ChatCompletionsResponse, ChatMessage};
use crate::ticket::{DummyTicketSource, FileTicketSource, TicketSource};
use crate::token_class::TokenClass;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use url::Url;

/// Default encrypted inference path exposed by the gateway.
pub const GATEWAY_INFER_PATH: &str = "/v1/infer";

/// Encrypted forwarding path exposed by the privacy relay.
pub const RELAY_INFER_PATH: &str = "/relay";

/// Where the application should load usage tickets from.
#[derive(Debug, Clone)]
pub enum TicketSourceConfig {
    /// Development-only mode. Requires a gateway running with the dummy verifier.
    Dummy,
    /// Load pre-issued tickets from a JSON file.
    File(PathBuf),
}

impl TicketSourceConfig {
    async fn load(&self) -> Result<Arc<dyn TicketSource>> {
        match self {
            TicketSourceConfig::Dummy => {
                let source: Arc<dyn TicketSource> = DummyTicketSource::new();
                Ok(source)
            }
            TicketSourceConfig::File(path) => {
                let source: Arc<dyn TicketSource> = FileTicketSource::from_path(path).await?;
                Ok(source)
            }
        }
    }
}

/// High-level configuration that another Rust app can own directly.
///
/// `from_env` recognizes:
/// - `GATEWAY_BASE_URL` or `GATEWAY_URL`
/// - `GATEWAY_PUBLIC_KEY_B64`
/// - `GATEWAY_TICKETS_JSON` or `TICKETS_JSON`
/// - `GATEWAY_USE_DUMMY_TICKETS=true` for dev
/// - `GATEWAY_INFER_PATH` or `GATEWAY_USE_RELAY=true`
/// - `GATEWAY_MODEL` or `MODEL`
/// - `GATEWAY_TOKEN_CLASS` or `TOKEN_CLASS`
/// - `GATEWAY_TEMPERATURE`
/// - `GATEWAY_TIMEOUT_SECS`
/// - `GATEWAY_AUTH_BEARER`
#[derive(Debug, Clone)]
pub struct AppGatewayConfig {
    pub endpoint: Url,
    pub infer_path: String,
    pub gateway_public_key: GatewayPublicKey,
    pub auth_bearer: Option<String>,
    pub tickets: TicketSourceConfig,
    pub model: String,
    pub token_class: TokenClass,
    pub temperature: Option<f32>,
    pub timeout_secs: u64,
}

impl AppGatewayConfig {
    pub fn new(
        endpoint: Url,
        gateway_public_key: GatewayPublicKey,
        tickets: TicketSourceConfig,
        model: impl Into<String>,
        token_class: TokenClass,
    ) -> Self {
        Self {
            endpoint,
            infer_path: GATEWAY_INFER_PATH.to_string(),
            gateway_public_key,
            auth_bearer: None,
            tickets,
            model: model.into(),
            token_class,
            temperature: None,
            timeout_secs: 60,
        }
    }

    pub fn with_infer_path(mut self, infer_path: impl Into<String>) -> Self {
        self.infer_path = infer_path.into();
        self
    }

    pub fn use_gateway_path(self) -> Self {
        self.with_infer_path(GATEWAY_INFER_PATH)
    }

    pub fn use_relay_path(self) -> Self {
        self.with_infer_path(RELAY_INFER_PATH)
    }

    pub fn with_auth_bearer(mut self, bearer: impl Into<String>) -> Self {
        self.auth_bearer = Some(bearer.into());
        self
    }

    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    pub fn with_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    pub fn from_env() -> Result<Self> {
        let endpoint_raw = required_env(&["GATEWAY_BASE_URL", "GATEWAY_URL"])?;
        let endpoint = endpoint_raw.parse::<Url>()?;

        let pk_b64 = required_env(&["GATEWAY_PUBLIC_KEY_B64"])?;
        let gateway_public_key = GatewayPublicKey::from_base64(&pk_b64)?;

        let use_relay = match first_env(&["GATEWAY_USE_RELAY"]) {
            Some(raw) => parse_bool(&raw, "GATEWAY_USE_RELAY")?,
            None => false,
        };

        let infer_path = first_env(&["GATEWAY_INFER_PATH"]).unwrap_or_else(|| {
            if use_relay {
                RELAY_INFER_PATH.to_string()
            } else {
                GATEWAY_INFER_PATH.to_string()
            }
        });

        let tickets = if let Some(path) = first_env(&["GATEWAY_TICKETS_JSON", "TICKETS_JSON"]) {
            TicketSourceConfig::File(PathBuf::from(path))
        } else if let Some(raw) = first_env(&["GATEWAY_USE_DUMMY_TICKETS"]) {
            if parse_bool(&raw, "GATEWAY_USE_DUMMY_TICKETS")? {
                TicketSourceConfig::Dummy
            } else {
                return Err(Error::TicketSource(
                    "set GATEWAY_TICKETS_JSON or GATEWAY_USE_DUMMY_TICKETS=true".to_string(),
                ));
            }
        } else {
            return Err(Error::TicketSource(
                "set GATEWAY_TICKETS_JSON or GATEWAY_USE_DUMMY_TICKETS=true".to_string(),
            ));
        };

        let model =
            first_env(&["GATEWAY_MODEL", "MODEL"]).unwrap_or_else(|| "gpt-4o-mini".to_string());

        let token_class = match first_env(&["GATEWAY_TOKEN_CLASS", "TOKEN_CLASS"]) {
            Some(raw) => raw.parse::<TokenClass>()?,
            None => TokenClass::C2048,
        };

        let temperature = match first_env(&["GATEWAY_TEMPERATURE"]) {
            Some(raw) => Some(parse_f32(&raw, "GATEWAY_TEMPERATURE")?),
            None => None,
        };

        let timeout_secs = match first_env(&["GATEWAY_TIMEOUT_SECS"]) {
            Some(raw) => parse_u64(&raw, "GATEWAY_TIMEOUT_SECS")?,
            None => 60,
        };

        Ok(Self {
            endpoint,
            infer_path,
            gateway_public_key,
            auth_bearer: first_env(&["GATEWAY_AUTH_BEARER"]),
            tickets,
            model,
            token_class,
            temperature,
            timeout_secs,
        })
    }

    pub async fn build(self) -> Result<AppGateway> {
        let tickets = self.tickets.load().await?;

        let mut client_config = GatewayClientConfig::default();
        client_config.infer_path = self.infer_path.clone();
        client_config.auth_bearer = self.auth_bearer.clone();
        client_config.timeout_secs = self.timeout_secs;

        let client = GatewayClient::with_config(
            self.endpoint.clone(),
            self.gateway_public_key,
            tickets,
            client_config,
        )?;

        Ok(AppGateway {
            client,
            default_model: self.model,
            default_token_class: self.token_class,
            default_temperature: self.temperature,
        })
    }
}

/// Per-request overrides for the app-facing helper.
#[derive(Debug, Clone, Default)]
pub struct AppChatRequest {
    pub system_prompt: Option<String>,
    pub messages: Vec<ChatMessage>,
    pub model: Option<String>,
    pub token_class: Option<TokenClass>,
    pub temperature: Option<f32>,
}

impl AppChatRequest {
    pub fn new(messages: Vec<ChatMessage>) -> Self {
        Self {
            messages,
            ..Default::default()
        }
    }

    pub fn from_user_prompt(user_prompt: impl Into<String>) -> Self {
        Self::new(vec![ChatMessage::user(user_prompt)])
    }

    pub fn with_system_prompt(mut self, system_prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(system_prompt.into());
        self
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    pub fn with_token_class(mut self, token_class: TokenClass) -> Self {
        self.token_class = Some(token_class);
        self
    }

    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }
}

/// Thin wrapper for application code that wants a ready-to-use gateway client.
#[derive(Debug, Clone)]
pub struct AppGateway {
    client: GatewayClient,
    default_model: String,
    default_token_class: TokenClass,
    default_temperature: Option<f32>,
}

impl AppGateway {
    pub fn client(&self) -> &GatewayClient {
        &self.client
    }

    pub fn default_model(&self) -> &str {
        &self.default_model
    }

    pub fn default_token_class(&self) -> TokenClass {
        self.default_token_class
    }

    pub async fn ask(&self, user_prompt: impl Into<String>) -> Result<String> {
        let response = self
            .chat(AppChatRequest::from_user_prompt(user_prompt))
            .await?;
        Ok(response.first_text().unwrap_or_default().to_string())
    }

    pub async fn ask_with_system(
        &self,
        system_prompt: impl Into<String>,
        user_prompt: impl Into<String>,
    ) -> Result<String> {
        let request =
            AppChatRequest::from_user_prompt(user_prompt).with_system_prompt(system_prompt);
        let response = self.chat(request).await?;
        Ok(response.first_text().unwrap_or_default().to_string())
    }

    pub async fn chat(&self, request: AppChatRequest) -> Result<ChatCompletionsResponse> {
        if request.messages.is_empty() {
            return Err(Error::Protocol(
                "chat request must include at least one message".to_string(),
            ));
        }

        let token_class = request.token_class.unwrap_or(self.default_token_class);
        let model = request.model.unwrap_or_else(|| self.default_model.clone());
        let temperature = request.temperature.or(self.default_temperature);

        let mut messages = Vec::with_capacity(
            request.messages.len() + usize::from(request.system_prompt.is_some()),
        );

        if let Some(system_prompt) = request.system_prompt {
            messages.push(ChatMessage::system(system_prompt));
        }
        messages.extend(request.messages);

        let req = ChatCompletionsRequest {
            model,
            messages,
            temperature,
            max_tokens: None,
            stream: Some(false),
            extra: Default::default(),
        };

        self.client.chat_completions(token_class, req).await
    }
}

fn first_env(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| match env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    })
}

fn required_env(keys: &[&str]) -> Result<String> {
    first_env(keys).ok_or_else(|| {
        Error::Protocol(format!(
            "missing environment variable; set one of {}",
            keys.join(", ")
        ))
    })
}

fn parse_bool(raw: &str, key: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(Error::Protocol(format!(
            "{key} must be one of true/false/1/0/yes/no/on/off"
        ))),
    }
}

fn parse_f32(raw: &str, key: &str) -> Result<f32> {
    raw.trim()
        .parse::<f32>()
        .map_err(|_| Error::Protocol(format!("{key} must be a floating-point number")))
}

fn parse_u64(raw: &str, key: &str) -> Result<u64> {
    raw.trim()
        .parse::<u64>()
        .map_err(|_| Error::Protocol(format!("{key} must be an unsigned integer")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_boolean_variants() {
        assert!(parse_bool("true", "KEY").unwrap());
        assert!(parse_bool("YES", "KEY").unwrap());
        assert!(!parse_bool("0", "KEY").unwrap());
        assert!(parse_bool("maybe", "KEY").is_err());
    }

    #[test]
    fn builds_user_prompt_request() {
        let request = AppChatRequest::from_user_prompt("hello")
            .with_system_prompt("system")
            .with_model("gpt-4o-mini")
            .with_token_class(TokenClass::C1024)
            .with_temperature(0.1);

        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.messages[0].role, "user");
        assert_eq!(request.system_prompt.as_deref(), Some("system"));
        assert_eq!(request.model.as_deref(), Some("gpt-4o-mini"));
        assert_eq!(request.token_class, Some(TokenClass::C1024));
        assert_eq!(request.temperature, Some(0.1));
    }
}
