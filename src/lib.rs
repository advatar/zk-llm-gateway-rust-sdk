//! zk-llm-gateway-sdk
//!
//! A Rust SDK for calling a ZK LLM Gateway using:
//! - end-to-end encrypted envelopes (client -> gateway)
//! - token-class request/response padding
//! - ZK-ready usage tickets (nullifiers + proof payload)

mod client;
mod crypto;
mod error;
mod padding;
mod token_class;

pub mod openai;
pub mod ticket;

#[cfg(feature = "redaction")]
pub mod redaction;

pub use crate::client::{GatewayClient, GatewayClientConfig};
pub use crate::crypto::{GatewayPublicKey, Envelope};
pub use crate::error::{Error, Result};
pub use crate::token_class::TokenClass;
