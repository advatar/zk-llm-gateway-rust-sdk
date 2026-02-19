use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// TokenClass represents a coarse bucket for request/response size shaping.
///
/// These values intentionally match the gateway's canonical protocol in
/// `zk-llm-gateway/common/src/token.rs`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenClass {
    C256,
    C512,
    C1024,
    C2048,
    C4096,
}

impl TokenClass {
    /// Maximum prompt bytes accepted by the gateway's coarse guardrail.
    pub fn max_prompt_bytes(&self) -> usize {
        match self {
            TokenClass::C256 => 2 * 1024,
            TokenClass::C512 => 4 * 1024,
            TokenClass::C1024 => 8 * 1024,
            TokenClass::C2048 => 16 * 1024,
            TokenClass::C4096 => 32 * 1024,
        }
    }

    /// Maximum completion tokens accepted by the gateway policy.
    pub fn max_completion_tokens(&self) -> u32 {
        match self {
            TokenClass::C256 => 256,
            TokenClass::C512 => 512,
            TokenClass::C1024 => 1024,
            TokenClass::C2048 => 2048,
            TokenClass::C4096 => 4096,
        }
    }

    /// Target request plaintext size before encryption.
    pub fn request_padded_len(&self) -> usize {
        match self {
            TokenClass::C256 => 8 * 1024,
            TokenClass::C512 => 12 * 1024,
            TokenClass::C1024 => 20 * 1024,
            TokenClass::C2048 => 36 * 1024,
            TokenClass::C4096 => 68 * 1024,
        }
    }

    /// Target response plaintext size before encryption.
    pub fn response_padded_len(&self) -> usize {
        match self {
            TokenClass::C256 => 8 * 1024,
            TokenClass::C512 => 16 * 1024,
            TokenClass::C1024 => 32 * 1024,
            TokenClass::C2048 => 64 * 1024,
            TokenClass::C4096 => 128 * 1024,
        }
    }

    pub fn max_output_tokens_hint(&self) -> u32 {
        self.max_completion_tokens()
    }

    pub fn id_u8(&self) -> u8 {
        match self {
            TokenClass::C256 => 1,
            TokenClass::C512 => 2,
            TokenClass::C1024 => 3,
            TokenClass::C2048 => 4,
            TokenClass::C4096 => 5,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TokenClass::C256 => "c256",
            TokenClass::C512 => "c512",
            TokenClass::C1024 => "c1024",
            TokenClass::C2048 => "c2048",
            TokenClass::C4096 => "c4096",
        }
    }
}

impl fmt::Display for TokenClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TokenClass {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim().to_lowercase();
        match s.as_str() {
            "c256" | "256" => Ok(TokenClass::C256),
            "c512" | "512" => Ok(TokenClass::C512),
            "c1024" | "1024" => Ok(TokenClass::C1024),
            "c2048" | "2048" => Ok(TokenClass::C2048),
            "c4096" | "4096" => Ok(TokenClass::C4096),
            _ => Err(Error::InvalidTokenClass(s)),
        }
    }
}
