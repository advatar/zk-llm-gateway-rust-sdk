use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// TokenClass represents a coarse bucket for request/response size shaping.
///
/// The SDK uses token classes to choose a fixed padded byte size for:
/// - encrypted request plaintext
/// - encrypted response plaintext
///
/// This reduces metadata leakage from variable request sizes.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenClass {
    /// ~512 tokens
    C512,
    /// ~1024 tokens
    C1024,
    /// ~2048 tokens
    C2048,
    /// ~4096 tokens
    C4096,
}

impl TokenClass {
    /// Max plaintext bytes for a request in this class.
    ///
    /// This is a pragmatic constant (not a hard token count); apps should still
    /// minimize context and avoid sending identifying blobs.
    pub fn request_padded_len(&self) -> usize {
        match self {
            TokenClass::C512 => 8 * 1024,
            TokenClass::C1024 => 16 * 1024,
            TokenClass::C2048 => 32 * 1024,
            TokenClass::C4096 => 64 * 1024,
        }
    }

    /// Max plaintext bytes for a response in this class.
    pub fn response_padded_len(&self) -> usize {
        match self {
            TokenClass::C512 => 8 * 1024,
            TokenClass::C1024 => 16 * 1024,
            TokenClass::C2048 => 32 * 1024,
            TokenClass::C4096 => 64 * 1024,
        }
    }

    /// A rough maximum for `max_tokens` that apps can use as a hint.
    /// Gateways may enforce their own policy.
    pub fn max_output_tokens_hint(&self) -> u32 {
        match self {
            TokenClass::C512 => 512,
            TokenClass::C1024 => 1024,
            TokenClass::C2048 => 2048,
            TokenClass::C4096 => 4096,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
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
            "c512" | "512" => Ok(TokenClass::C512),
            "c1024" | "1024" => Ok(TokenClass::C1024),
            "c2048" | "2048" => Ok(TokenClass::C2048),
            "c4096" | "4096" => Ok(TokenClass::C4096),
            _ => Err(Error::InvalidTokenClass(s)),
        }
    }
}
