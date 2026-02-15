//! ZK-ready usage tickets.
//!
//! The gateway verifies tickets and enforces replay protection using a nullifier.
//! This SDK treats tickets as an opaque payload and provides simple sources.

use crate::error::{Error, Result};
use crate::token_class::TokenClass;
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A ZK-ready ticket payload.
///
/// Fields are intentionally generic and opaque.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkTicket {
    /// Base64-encoded nullifier. Must be unique per spend.
    pub nullifier_b64: String,

    /// Base64-encoded proof blob (ZK proof, TEE attestation, etc.).
    pub proof_b64: String,

    /// Optional base64-encoded commitment/accumulator root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment_root_b64: Option<String>,

    /// Optional extra data for custom verifiers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,

    /// Optional id useful for debugging / receipts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_id: Option<String>,
}

impl ZkTicket {
    pub fn random_dummy() -> Self {
        let mut n = [0u8; 32];
        OsRng.fill_bytes(&mut n);
        Self {
            nullifier_b64: general_purpose::STANDARD.encode(n),
            proof_b64: general_purpose::STANDARD.encode([]),
            commitment_root_b64: None,
            extra: None,
            ticket_id: None,
        }
    }
}

#[async_trait]
pub trait TicketSource: Send + Sync {
    async fn next_ticket(&self, token_class: TokenClass) -> Result<ZkTicket>;
}

/// Development-only ticket source.
#[derive(Debug, Default)]
pub struct DummyTicketSource;

impl DummyTicketSource {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

#[async_trait]
impl TicketSource for DummyTicketSource {
    async fn next_ticket(&self, _token_class: TokenClass) -> Result<ZkTicket> {
        Ok(ZkTicket::random_dummy())
    }
}

/// A ticket pool loaded from a JSON file.
///
/// The file format is a JSON array of `ZkTicket` objects.
#[derive(Debug)]
pub struct FileTicketSource {
    inner: Mutex<VecDeque<ZkTicket>>,
}

impl FileTicketSource {
    pub async fn from_path(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let bytes = tokio::fs::read(path).await?;
        let tickets: Vec<ZkTicket> = serde_json::from_slice(&bytes)?;
        let mut dq = VecDeque::new();
        for t in tickets {
            dq.push_back(t);
        }
        Ok(Arc::new(Self {
            inner: Mutex::new(dq),
        }))
    }

    pub async fn remaining(&self) -> usize {
        let g = self.inner.lock().await;
        g.len()
    }
}

#[async_trait]
impl TicketSource for FileTicketSource {
    async fn next_ticket(&self, _token_class: TokenClass) -> Result<ZkTicket> {
        let mut g = self.inner.lock().await;
        g.pop_front().ok_or(Error::TicketExhausted)
    }
}
