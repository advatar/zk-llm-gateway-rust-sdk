//! ZK-ready usage tickets.
//!
//! This module mirrors the gateway's canonical ticket shape used by
//! `zk-llm-gateway/common/src/zk.rs`.

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkTicket {
    /// Base64 bytes (commitment/accumulator root).
    #[serde(alias = "commitment_root_b64")]
    pub commitment_root: String,

    /// Base64 bytes, unique per spend.
    #[serde(alias = "nullifier_b64")]
    pub nullifier: String,

    /// Class bound by the proof.
    pub token_class: TokenClass,

    /// Base64 proof bytes.
    #[serde(alias = "proof_b64")]
    pub proof: String,
}

impl ZkTicket {
    pub fn random_dummy(token_class: TokenClass) -> Self {
        let mut root = [0u8; 32];
        let mut nullifier = [0u8; 32];
        let mut proof = [0u8; 64];
        OsRng.fill_bytes(&mut root);
        OsRng.fill_bytes(&mut nullifier);
        OsRng.fill_bytes(&mut proof);

        Self {
            commitment_root: general_purpose::STANDARD.encode(root),
            nullifier: general_purpose::STANDARD.encode(nullifier),
            token_class,
            proof: general_purpose::STANDARD.encode(proof),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RawTicket {
    #[serde(default)]
    commitment_root: Option<String>,
    #[serde(default)]
    commitment_root_b64: Option<String>,

    #[serde(default)]
    nullifier: Option<String>,
    #[serde(default)]
    nullifier_b64: Option<String>,

    #[serde(default)]
    token_class: Option<TokenClass>,

    #[serde(default)]
    proof: Option<String>,
    #[serde(default)]
    proof_b64: Option<String>,
}

impl RawTicket {
    fn into_ticket(self, token_class: TokenClass) -> Result<ZkTicket> {
        let commitment_root = self
            .commitment_root
            .or(self.commitment_root_b64)
            .unwrap_or_else(|| general_purpose::STANDARD.encode([0u8; 32]));

        let nullifier = self.nullifier.or(self.nullifier_b64).ok_or_else(|| {
            Error::TicketSource("ticket missing nullifier/nullifier_b64".to_string())
        })?;

        let proof = self.proof.or(self.proof_b64).unwrap_or_default();

        Ok(ZkTicket {
            commitment_root,
            nullifier,
            token_class: self.token_class.unwrap_or(token_class),
            proof,
        })
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
    async fn next_ticket(&self, token_class: TokenClass) -> Result<ZkTicket> {
        Ok(ZkTicket::random_dummy(token_class))
    }
}

/// A ticket pool loaded from a JSON file.
#[derive(Debug)]
pub struct FileTicketSource {
    inner: Mutex<VecDeque<RawTicket>>,
}

impl FileTicketSource {
    pub async fn from_path(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let bytes = tokio::fs::read(path).await?;
        let tickets: Vec<RawTicket> = serde_json::from_slice(&bytes)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(VecDeque::from(tickets)),
        }))
    }

    pub async fn remaining(&self) -> usize {
        let g = self.inner.lock().await;
        g.len()
    }
}

#[async_trait]
impl TicketSource for FileTicketSource {
    async fn next_ticket(&self, token_class: TokenClass) -> Result<ZkTicket> {
        let mut g = self.inner.lock().await;

        // Prefer exact class matches, then class-agnostic entries.
        let exact_idx = g
            .iter()
            .position(|t| t.token_class.map(|tc| tc == token_class).unwrap_or(false));
        let fallback_idx = g.iter().position(|t| t.token_class.is_none());

        let idx = exact_idx.or(fallback_idx).ok_or(Error::TicketExhausted)?;
        let raw = g.remove(idx).ok_or(Error::TicketExhausted)?;

        let ticket = raw.into_ticket(token_class)?;
        if ticket.token_class != token_class {
            return Err(Error::TicketSource(
                "ticket token_class does not match requested class".to_string(),
            ));
        }

        Ok(ticket)
    }
}
