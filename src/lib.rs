//! zk-llm-gateway-sdk
//!
//! A Rust SDK for calling a ZK LLM Gateway using:
//! - end-to-end encrypted envelopes (client -> gateway)
//! - token-class request/response padding
//! - ZK-ready usage tickets (nullifiers + proof payload)

mod client;
mod crypto;
mod error;
pub mod integration;
mod padding;
mod token_class;

pub mod openai;
pub mod ticket;

#[cfg(feature = "redaction")]
pub mod redaction;

pub use crate::client::{GatewayClient, GatewayClientConfig};
pub use crate::crypto::{Envelope, GatewayPublicKey};
pub use crate::error::{Error, Result};
pub use crate::integration::{
    AppChatRequest, AppGateway, AppGatewayConfig, TicketSourceConfig, GATEWAY_INFER_PATH,
    RELAY_INFER_PATH,
};
pub use crate::token_class::TokenClass;
