//! Redaction helpers.
//!
//! These utilities can reduce accidental leakage of obvious identifiers
//! (emails, phone numbers, API keys) *before* sending a prompt to a remote model.
//!
//! They do not provide perfect privacy: content, writing style, and context can
//! still identify a user.

use crate::error::Result;
use rand::rngs::OsRng;
use rand::RngCore;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RedactionMode {
    /// Same input value maps to the same placeholder for the lifetime of the Redactor.
    StablePerValue,
    /// Each redaction occurrence gets a unique placeholder.
    Ephemeral,
}

#[derive(Debug, Clone)]
pub struct RedactionResult {
    pub redacted: String,
    /// placeholder -> original
    pub map: HashMap<String, String>,
}

#[derive(Debug)]
pub struct Redactor {
    mode: RedactionMode,
    salt: [u8; 16],
    patterns: Vec<(RedactionKind, Regex)>,
    custom_terms: Vec<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RedactionKind {
    Email,
    Phone,
    EthAddress,
    ApiKey,
    PrivateKeyBlock,
}

impl RedactionKind {
    fn label(&self) -> &'static str {
        match self {
            RedactionKind::Email => "EMAIL",
            RedactionKind::Phone => "PHONE",
            RedactionKind::EthAddress => "ETH",
            RedactionKind::ApiKey => "APIKEY",
            RedactionKind::PrivateKeyBlock => "PRIVKEY",
        }
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new(RedactionMode::StablePerValue)
    }
}

impl Redactor {
    pub fn new(mode: RedactionMode) -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        // Pragmatic patterns. Tune for your product.
        let email = Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b").unwrap();
        let phone = Regex::new(r"\b\+?[0-9][0-9() \-]{7,}[0-9]\b").unwrap();
        let eth = Regex::new(r"\b0x[a-fA-F0-9]{40}\b").unwrap();
        let apikey = Regex::new(r"\b(sk-[A-Za-z0-9]{16,})\b").unwrap();
        let privkey = Regex::new(
            r"-----BEGIN[\s\S]*?PRIVATE KEY-----[\s\S]*?-----END[\s\S]*?PRIVATE KEY-----",
        )
        .unwrap();

        Self {
            mode,
            salt,
            patterns: vec![
                (RedactionKind::PrivateKeyBlock, privkey),
                (RedactionKind::ApiKey, apikey),
                (RedactionKind::EthAddress, eth),
                (RedactionKind::Email, email),
                (RedactionKind::Phone, phone),
            ],
            custom_terms: Vec::new(),
        }
    }

    pub fn add_custom_term(&mut self, term: impl Into<String>) {
        let t = term.into();
        if !t.is_empty() {
            self.custom_terms.push(t);
        }
    }

    pub fn redact_text(&self, input: &str) -> RedactionResult {
        let mut out = input.to_string();
        let mut map: HashMap<String, String> = HashMap::new();

        // Custom terms first (exact match, case sensitive).
        for term in &self.custom_terms {
            if out.contains(term) {
                let placeholder = self.placeholder("TERM", term, map.len());
                out = out.replace(term, &placeholder);
                map.insert(placeholder, term.clone());
            }
        }

        for (kind, re) in &self.patterns {
            // We need to iteratively replace because regex::replace_all doesn't give us easy stable mapping
            // with our own placeholder generation.
            loop {
                if let Some(m) = re.find(&out) {
                    let s = m.as_str().to_string();
                    let placeholder = self.placeholder(kind.label(), &s, map.len());
                    out.replace_range(m.range(), &placeholder);
                    map.insert(placeholder, s);
                } else {
                    break;
                }
            }
        }

        RedactionResult { redacted: out, map }
    }

    /// Redact all string leaf nodes in a JSON value.
    pub fn redact_json(
        &self,
        value: &serde_json::Value,
    ) -> Result<(serde_json::Value, HashMap<String, String>)> {
        let mut map: HashMap<String, String> = HashMap::new();
        let v = self.redact_json_inner(value, &mut map)?;
        Ok((v, map))
    }

    fn redact_json_inner(
        &self,
        value: &serde_json::Value,
        map: &mut HashMap<String, String>,
    ) -> Result<serde_json::Value> {
        match value {
            serde_json::Value::String(s) => {
                let r = self.redact_text(s);
                for (k, v) in r.map {
                    map.insert(k, v);
                }
                Ok(serde_json::Value::String(r.redacted))
            }
            serde_json::Value::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for v in arr {
                    out.push(self.redact_json_inner(v, map)?);
                }
                Ok(serde_json::Value::Array(out))
            }
            serde_json::Value::Object(obj) => {
                let mut out = serde_json::Map::new();
                for (k, v) in obj {
                    out.insert(k.clone(), self.redact_json_inner(v, map)?);
                }
                Ok(serde_json::Value::Object(out))
            }
            _ => Ok(value.clone()),
        }
    }

    pub fn rehydrate_text(&self, input: &str, map: &HashMap<String, String>) -> String {
        let mut out = input.to_string();
        // Replace longer placeholders first to avoid partial overlaps.
        let mut keys: Vec<&String> = map.keys().collect();
        keys.sort_by_key(|k| std::cmp::Reverse(k.len()));
        for k in keys {
            if let Some(v) = map.get(k) {
                out = out.replace(k.as_str(), v.as_str());
            }
        }
        out
    }

    fn placeholder(&self, label: &str, original: &str, counter: usize) -> String {
        match self.mode {
            RedactionMode::StablePerValue => {
                let mut hasher = Sha256::new();
                hasher.update(&self.salt);
                hasher.update(label.as_bytes());
                hasher.update(original.as_bytes());
                let digest = hasher.finalize();
                let short = hex(&digest[..6]);
                format!("<{}_{}>", label, short)
            }
            RedactionMode::Ephemeral => {
                let mut hasher = Sha256::new();
                hasher.update(&self.salt);
                hasher.update(label.as_bytes());
                hasher.update(counter.to_le_bytes());
                hasher.update(original.as_bytes());
                let digest = hasher.finalize();
                let short = hex(&digest[..6]);
                format!("<{}_{}>", label, short)
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
