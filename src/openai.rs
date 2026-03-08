//! Lightweight OpenAI-style types.
//!
//! This module intentionally covers only a small subset of the schema.
//! `GatewayClient::infer_json` and `GatewayClient::chat_completions` both
//! target the gateway's canonical `InferenceRequest` protocol.

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    #[serde(default, deserialize_with = "deserialize_chat_message_content")]
    pub content: String,
    #[serde(default, flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: "system".to_string(),
            content: content.into(),
            extra: HashMap::new(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".to_string(),
            content: content.into(),
            extra: HashMap::new(),
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: "assistant".to_string(),
            content: content.into(),
            extra: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionsRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,

    /// Extra parameters forwarded to the upstream provider.
    ///
    /// `stream=true` is rejected on the canonical `/v1/infer` path because the
    /// encrypted response is non-streaming today.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionsResponse {
    #[serde(default)]
    pub id: Option<String>,

    #[serde(default)]
    pub model: Option<String>,

    pub choices: Vec<ChatChoice>,

    #[serde(default)]
    pub usage: Option<Usage>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatChoice {
    pub index: u32,

    #[serde(default)]
    pub message: Option<ChatMessage>,

    #[serde(default)]
    pub finish_reason: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub prompt_tokens: Option<u32>,
    #[serde(default)]
    pub completion_tokens: Option<u32>,
    #[serde(default)]
    pub total_tokens: Option<u32>,
}

impl ChatCompletionsResponse {
    pub fn first_text(&self) -> Option<&str> {
        self.choices
            .iter()
            .filter_map(|c| c.message.as_ref())
            .map(|m| m.content.as_str())
            .next()
    }
}

fn deserialize_chat_message_content<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None | Some(serde_json::Value::Null) => Ok(String::new()),
        Some(serde_json::Value::String(s)) => Ok(s),
        Some(other) => serde_json::to_string(&other).map_err(serde::de::Error::custom),
    }
}
