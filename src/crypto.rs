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
    #[serde(alias = "version")]
    pub v: u8,
    pub token_class: TokenClass,

    /// Gateway canonical field name is `eph_pubkey_b64`.
    /// Accept legacy `kem_pub_b64` when deserializing.
    #[serde(alias = "kem_pub_b64")]
    pub eph_pubkey_b64: String,

    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SealState {
    pub token_class: TokenClass,
    pub eph_pubkey: [u8; 32],
    pub resp_key: [u8; 32],
}

#[derive(Debug, Copy, Clone)]
enum KeyDirection {
    Request,
    Response,
}

fn aad(v: u8, token_class: TokenClass, dir: KeyDirection) -> Vec<u8> {
    let d = match dir {
        KeyDirection::Request => 1u8,
        KeyDirection::Response => 2u8,
    };
    vec![v, token_class.id_u8(), d]
}

fn hkdf_info(token_class: TokenClass, dir: KeyDirection) -> Vec<u8> {
    let mut v = b"zk-llm-gateway-envelope-v1".to_vec();
    match dir {
        KeyDirection::Request => v.extend_from_slice(b"/req"),
        KeyDirection::Response => v.extend_from_slice(b"/resp"),
    }
    v.push(token_class.id_u8());
    v
}

fn derive_key(shared_secret: &[u8; 32], token_class: TokenClass, dir: KeyDirection) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(&hkdf_info(token_class, dir), &mut okm)
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

    let raw = serde_json::to_vec(json)?;
    let padded = pad_payload(&raw, token_class.request_padded_len())?;

    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let eph_public = PublicKey::from(&eph_secret);
    let eph_pub_bytes = eph_public.to_bytes();

    let shared = eph_secret.diffie_hellman(&gateway_pk.as_public_key());
    let shared_bytes = shared.to_bytes();
    let req_key = derive_key(&shared_bytes, token_class, KeyDirection::Request);
    let resp_key = derive_key(&shared_bytes, token_class, KeyDirection::Response);

    let cipher = ChaCha20Poly1305::new(&req_key.into());

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let a = aad(v, token_class, KeyDirection::Request);
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
        resp_key,
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

    // Expect gateway to echo the ephemeral request public key.
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

    let cipher = ChaCha20Poly1305::new(&st.resp_key.into());
    let a = aad(env.v, env.token_class, KeyDirection::Response);
    let nonce_ga = nonce.into();
    let padded = cipher
        .decrypt(&nonce_ga, Payload { msg: &ct, aad: &a })
        .map_err(|_| Error::Crypto)?;

    let raw = unpad_payload(&padded)?;
    let json = serde_json::from_slice::<serde_json::Value>(&raw)?;
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::padding::pad_payload;
    use base64::engine::general_purpose;
    use chacha20poly1305::{aead::Aead, aead::Payload, ChaCha20Poly1305, KeyInit};
    use rand::RngCore;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let gw_secret = StaticSecret::random_from_rng(OsRng);
        let gw_public = PublicKey::from(&gw_secret);
        let gateway_pk = GatewayPublicKey(gw_public.to_bytes());

        let token_class = TokenClass::C1024;
        let req_json = serde_json::json!({"hello": "world"});
        let (env_req, st) = seal_json(&gateway_pk, token_class, &req_json).unwrap();

        // Gateway side: derive shared secret using request eph pubkey.
        let eph_pub_bytes = general_purpose::STANDARD
            .decode(env_req.eph_pubkey_b64)
            .unwrap();
        let mut eph_pub_arr = [0u8; 32];
        eph_pub_arr.copy_from_slice(&eph_pub_bytes);
        let eph_pub = PublicKey::from(eph_pub_arr);
        let shared = gw_secret.diffie_hellman(&eph_pub);
        let shared_bytes = shared.to_bytes();

        let resp_key = derive_key(&shared_bytes, token_class, KeyDirection::Response);

        assert_eq!(resp_key, st.resp_key);

        // Response is encrypted with response-direction key/AAD.
        let resp_json = serde_json::json!({"upstream": {"ok": true}});
        let raw = serde_json::to_vec(&resp_json).unwrap();
        let padded = pad_payload(&raw, token_class.response_padded_len()).unwrap();
        let cipher = ChaCha20Poly1305::new(&resp_key.into());

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let a = aad(env_req.v, token_class, KeyDirection::Response);
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
