use crate::error::{Error, Result};
use crate::padding::{pad_payload, unpad_payload};
use crate::token_class::TokenClass;
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::{aead::Aead, aead::Payload, ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// A base64-encoded gateway public key (X25519).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct GatewayPublicKey(pub(crate) [u8; 32]);

impl GatewayPublicKey {
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = general_purpose::STANDARD
            .decode(s.trim())
            .map_err(|e| Error::Base64(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(Error::InvalidGatewayPublicKey);
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&bytes);
        Ok(Self(pk))
    }

    pub fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.0)
    }

    pub(crate) fn as_public_key(&self) -> PublicKey {
        PublicKey::from(self.0)
    }
}

/// Envelope is the JSON wrapper sent to the gateway/relay.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Envelope {
    /// protocol version
    pub v: u8,
    pub token_class: TokenClass,
    pub eph_pubkey_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SealState {
    pub token_class: TokenClass,
    pub eph_pubkey: [u8; 32],
    pub key: [u8; 32],
}

fn aad(v: u8, token_class: TokenClass, eph_pubkey: &[u8; 32]) -> Vec<u8> {
    // Keep AAD deterministic and minimal. This is not secret.
    // Including eph_pubkey binds the ciphertext to the request keypair.
    let mut out = Vec::with_capacity(1 + 1 + 5 + 32);
    out.push(v);
    out.extend_from_slice(token_class.as_str().as_bytes());
    out.push(b'|');
    out.extend_from_slice(eph_pubkey);
    out
}

fn derive_key(shared_secret: &[u8; 32], v: u8, token_class: TokenClass) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    let info = format!("zk-llm-gateway|v{}|{}", v, token_class.as_str());
    hk.expand(info.as_bytes(), &mut okm)
        .expect("hkdf expand");
    okm
}

/// Encrypt + pad a JSON payload into an Envelope.
pub(crate) fn seal_json(
    gateway_pk: &GatewayPublicKey,
    token_class: TokenClass,
    json: &serde_json::Value,
) -> Result<(Envelope, SealState)> {
    let v = 1u8;

    // Serialize and pad
    let raw = serde_json::to_vec(json)?;
    let padded = pad_payload(&raw, token_class.request_padded_len())?;

    // Ephemeral X25519
    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let eph_public = PublicKey::from(&eph_secret);
    let eph_pub_bytes = eph_public.to_bytes();

    // Shared secret and AEAD key
    let shared = eph_secret.diffie_hellman(&gateway_pk.as_public_key());
    let shared_bytes = shared.to_bytes();
    let key = derive_key(&shared_bytes, v, token_class);
    let cipher = ChaCha20Poly1305::new(&key.into());

    // Nonce
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let a = aad(v, token_class, &eph_pub_bytes);
    let nonce_ga = nonce.into();
    let ct = cipher
        .encrypt(
            &nonce_ga,
            Payload {
                msg: &padded,
                aad: &a,
            },
        )
        .map_err(|_| Error::Crypto)?;

    let env = Envelope {
        v,
        token_class,
        eph_pubkey_b64: general_purpose::STANDARD.encode(eph_pub_bytes),
        nonce_b64: general_purpose::STANDARD.encode(nonce),
        ciphertext_b64: general_purpose::STANDARD.encode(ct),
    };

    let st = SealState {
        token_class,
        eph_pubkey: eph_pub_bytes,
        key,
    };

    Ok((env, st))
}

/// Decrypt an Envelope response using the SealState from the request.
pub(crate) fn open_json(env: &Envelope, st: &SealState) -> Result<serde_json::Value> {
    if env.v != 1 {
        return Err(Error::Crypto);
    }
    if env.token_class != st.token_class {
        return Err(Error::Crypto);
    }

    let eph_pub = general_purpose::STANDARD
        .decode(env.eph_pubkey_b64.trim())
        .map_err(|e| Error::Base64(e.to_string()))?;
    if eph_pub.len() != 32 {
        return Err(Error::Crypto);
    }
    let mut eph_pub_bytes = [0u8; 32];
    eph_pub_bytes.copy_from_slice(&eph_pub);

    // Expect gateway to echo the eph_pubkey from request.
    if eph_pub_bytes != st.eph_pubkey {
        return Err(Error::Crypto);
    }

    let nonce_bytes = general_purpose::STANDARD
        .decode(env.nonce_b64.trim())
        .map_err(|e| Error::Base64(e.to_string()))?;
    if nonce_bytes.len() != 12 {
        return Err(Error::Crypto);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);

    let ct = general_purpose::STANDARD
        .decode(env.ciphertext_b64.trim())
        .map_err(|e| Error::Base64(e.to_string()))?;

    let cipher = ChaCha20Poly1305::new(&st.key.into());
    let a = aad(env.v, env.token_class, &eph_pub_bytes);
    let nonce_ga = nonce.into();
    let padded = cipher
        .decrypt(
            &nonce_ga,
            Payload {
                msg: &ct,
                aad: &a,
            },
        )
        .map_err(|_| Error::Crypto)?;

    let raw = unpad_payload(&padded)?;
    let json = serde_json::from_slice::<serde_json::Value>(&raw)?;
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::padding::pad_payload;
    use base64::{engine::general_purpose, Engine as _};
    use chacha20poly1305::{aead::Aead, aead::Payload, ChaCha20Poly1305, KeyInit};
    use rand::RngCore;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        // Generate a random gateway keypair for the test.
        let gw_secret = StaticSecret::random_from_rng(OsRng);
        let gw_public = PublicKey::from(&gw_secret);
        let gateway_pk = GatewayPublicKey(gw_public.to_bytes());

        let token_class = TokenClass::C1024;
        let req_json = serde_json::json!({"hello": "world"});
        let (env_req, st) = seal_json(&gateway_pk, token_class, &req_json).unwrap();

        // Simulate gateway decrypting request: derive shared secret using gateway secret and eph pubkey.
        let eph_pub_bytes = general_purpose::STANDARD
            .decode(env_req.eph_pubkey_b64)
            .unwrap();
        let mut eph_pub_arr = [0u8; 32];
        eph_pub_arr.copy_from_slice(&eph_pub_bytes);
        let eph_pub = PublicKey::from(eph_pub_arr);
        let shared = gw_secret.diffie_hellman(&eph_pub);
        let key = derive_key(&shared.to_bytes(), env_req.v, env_req.token_class);
        assert_eq!(key, st.key);

        // Create a response encrypted with the same derived key and eph_pubkey.
        let resp_json = serde_json::json!({"upstream": {"ok": true}});
        let raw = serde_json::to_vec(&resp_json).unwrap();
        let padded = pad_payload(&raw, token_class.response_padded_len()).unwrap();
        let cipher = ChaCha20Poly1305::new(&key.into());
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let a = aad(env_req.v, token_class, &st.eph_pubkey);
        let nonce_ga = nonce.into();
        let ct = cipher
            .encrypt(
                &nonce_ga,
                Payload {
                    msg: &padded,
                    aad: &a,
                },
            )
            .unwrap();
        let env_resp = Envelope {
            v: env_req.v,
            token_class,
            eph_pubkey_b64: general_purpose::STANDARD.encode(st.eph_pubkey),
            nonce_b64: general_purpose::STANDARD.encode(nonce),
            ciphertext_b64: general_purpose::STANDARD.encode(ct),
        };

        let out = open_json(&env_resp, &st).unwrap();
        assert_eq!(out, resp_json);
    }
}
