use crate::error::{Error, Result};

const MAGIC: &[u8; 4] = b"ZKLG";
const HEADER_LEN: usize = 8;

/// Pads a plaintext payload to an exact target length.
///
/// The padded format is:
/// - 4 bytes: magic "ZKLG"
/// - 4 bytes: u32 payload length (little endian)
/// - N bytes: payload
/// - remaining: filler
pub fn pad_payload(payload: &[u8], target_len: usize) -> Result<Vec<u8>> {
    if target_len < HEADER_LEN {
        return Err(Error::InvalidPadding);
    }
    let max_payload = target_len - HEADER_LEN;
    if payload.len() > max_payload {
        return Err(Error::PayloadTooLarge {
            actual: payload.len(),
            limit: max_payload,
        });
    }

    let mut out = vec![0u8; target_len];
    out[..4].copy_from_slice(MAGIC);
    let len_u32 = u32::try_from(payload.len()).map_err(|_| Error::InvalidPadding)?;
    out[4..8].copy_from_slice(&len_u32.to_le_bytes());
    out[8..8 + payload.len()].copy_from_slice(payload);

    // Low-entropy filler to avoid accidentally creating token-like gibberish.
    // This filler is inside encrypted payload.
    let filler = b" \n";
    let mut i = 8 + payload.len();
    let mut j = 0usize;
    while i < target_len {
        out[i] = filler[j % filler.len()];
        i += 1;
        j += 1;
    }

    Ok(out)
}

/// Removes padding applied by `pad_payload`.
pub fn unpad_payload(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < HEADER_LEN {
        return Err(Error::InvalidPadding);
    }
    if &padded[..4] != MAGIC {
        return Err(Error::InvalidPadding);
    }
    let len = u32::from_le_bytes([padded[4], padded[5], padded[6], padded[7]]) as usize;
    if len > padded.len().saturating_sub(HEADER_LEN) {
        return Err(Error::InvalidPadding);
    }
    Ok(padded[8..8 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_roundtrip() {
        let msg = b"hello";
        let padded = pad_payload(msg, 64).unwrap();
        assert_eq!(padded.len(), 64);
        let unpadded = unpad_payload(&padded).unwrap();
        assert_eq!(unpadded, msg);
    }

    #[test]
    fn pad_rejects_too_large() {
        let msg = vec![0u8; 100];
        let err = pad_payload(&msg, 32).unwrap_err();
        match err {
            Error::PayloadTooLarge { .. } => {}
            _ => panic!("unexpected error: {err:?}"),
        }
    }
}
