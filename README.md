# zk-llm-gateway-sdk (Rust)

Rust SDK for integrating with a **ZK LLM Gateway** that supports:

- **End-to-end encrypted envelopes** (client → gateway) using X25519 + HKDF + ChaCha20-Poly1305
- **Token-class quantization + fixed-size padding** to reduce request-size fingerprinting
- **ZK-ready usage tickets** (nullifier + proof payload) via a pluggable `TicketSource`
- Optional **relay-compatible** mode (you can point the SDK at a relay URL; the relay only sees ciphertext)

This SDK is designed for **application developers** integrating with a hosted gateway.

> Security note: this SDK reduces linkage to *payment identity handles* and protects against relays/intermediaries reading prompts.
> It does **not** prevent the upstream model provider from correlating requests via *content*, timing, or other side channels.

---

## Quickstart

Add the dependency:

```toml
[dependencies]
zk-llm-gateway-sdk = "0.1"
```

Example: send an OpenAI-style Chat Completions request through the gateway.

```rust
use zk_llm_gateway_sdk::{
    GatewayClient, GatewayPublicKey, TokenClass,
    ticket::DummyTicketSource,
    openai::{ChatMessage, ChatCompletionsRequest},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1) Get your gateway URL (hosted gateway or relay URL).
    let endpoint = std::env::var("GATEWAY_URL")?;

    // 2) Get the gateway public key (base64-encoded 32 bytes).
    let pk_b64 = std::env::var("GATEWAY_PUBLIC_KEY_B64")?;
    let gateway_pk = GatewayPublicKey::from_base64(&pk_b64)?;

    // 3) Choose a token class. Larger classes reduce metadata leakage but cost more upstream.
    let token_class = TokenClass::C2048;

    // 4) Provide a ticket source. In production, use a real ticket pack / issuer.
    let tickets = DummyTicketSource::new();

    let client = GatewayClient::new(endpoint.parse()?, gateway_pk, tickets);

    let req = ChatCompletionsRequest {
        model: "gpt-4o-mini".to_string(),
        messages: vec![
            ChatMessage::system("You are a helpful assistant."),
            ChatMessage::user("Hello from a private agent client!"),
        ],
        temperature: Some(0.2),
        // The gateway may override max_tokens to the class maximum.
        max_tokens: None,
        stream: Some(false),
        extra: Default::default(),
    };

    let resp = client.chat_completions(token_class, req).await?;
    println!("{}", resp.first_text().unwrap_or_default());

    Ok(())
}
```

### Drop-in app module

If your Rust app just needs a small integration layer instead of wiring `GatewayClient`
manually, use `integration::AppGatewayConfig` and `integration::AppGateway`.

Environment variables:

- `GATEWAY_BASE_URL` or `GATEWAY_URL` - base URL for the gateway or relay host
- `GATEWAY_PUBLIC_KEY_B64` - base64 X25519 gateway public key
- `GATEWAY_TICKETS_JSON` or `TICKETS_JSON` - JSON file containing pre-issued tickets
- `GATEWAY_USE_DUMMY_TICKETS=true` - development-only fallback
- `GATEWAY_INFER_PATH=/relay` or `GATEWAY_USE_RELAY=true` - send ciphertext through the relay
- `GATEWAY_MODEL` or `MODEL` - default model name, defaults to `gpt-4o-mini`
- `GATEWAY_TOKEN_CLASS` or `TOKEN_CLASS` - defaults to `c2048`
- `GATEWAY_TEMPERATURE` - optional default temperature
- `GATEWAY_TIMEOUT_SECS` - optional request timeout, defaults to `60`
- `GATEWAY_AUTH_BEARER` - optional bearer token

```rust
use zk_llm_gateway_sdk::integration::AppGatewayConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let gateway = AppGatewayConfig::from_env()?.build().await?;

    let answer = gateway
        .ask_with_system("You are a helpful assistant.", "Summarize our privacy model.")
        .await?;

    println!("{answer}");
    Ok(())
}
```

For a complete executable example, see `examples/app_gateway.rs`.

---

## Concepts

### Token classes

A **token class** is a coarse “bucket” that sets a **fixed padded byte size** for requests and responses.

This helps reduce metadata leakage from variable request sizes (but does not eliminate timing/content correlation).

### Usage tickets

The gateway expects a ticket containing (at minimum):

- a **nullifier** (prevents replay / double-spend)
- a **proof payload** (ZK-ready field; opaque to the SDK)
- (optionally) an accumulator root / commitment root

This SDK models tickets as a simple serializable struct and lets you provide them via a `TicketSource`.

---

## Ticket sources

Included:

- `DummyTicketSource` (development only)
- `FileTicketSource` to load tickets from a JSON file and consume them sequentially

---

## Redaction helpers (optional)

Feature: `redaction` (enabled by default).

Provides a `Redactor` that can replace common identifiers (emails, phone numbers, API keys) with placeholders *before* sending to the gateway.

This is **not** a silver bullet, but it helps reduce accidental leakage.

---

## Repository layout

- `src/crypto.rs` — envelope encryption/decryption
- `src/token_class.rs` — token classes + fixed padded sizes
- `src/padding.rs` — padding/unpadding utilities
- `src/client.rs` — `GatewayClient`
- `src/integration.rs` — higher-level app wrapper and env-driven config
- `src/ticket.rs` — ticket types + ticket sources
- `src/openai.rs` — lightweight OpenAI-style request/response structs
- `src/redaction.rs` — optional redaction utilities

---

## License

Apache-2.0
