use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid base64: {0}")]
    Base64(String),

    #[error("invalid gateway public key")]
    InvalidGatewayPublicKey,

    #[error("invalid token class: {0}")]
    InvalidTokenClass(String),

    #[error("payload too large: {actual} bytes > class limit {limit} bytes")]
    PayloadTooLarge { actual: usize, limit: usize },

    #[error("invalid padded payload")]
    InvalidPadding,

    #[error("crypto error")]
    Crypto,

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("url error: {0}")]
    Url(#[from] url::ParseError),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ticket source exhausted")]
    TicketExhausted,

    #[error("ticket source error: {0}")]
    TicketSource(String),

    #[error("gateway returned error: {code}: {message}")]
    GatewayError { code: String, message: String },

    #[error("protocol error: {0}")]
    Protocol(String),
}
