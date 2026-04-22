/// SP 800-108r1 counter-mode KDF using HMAC-SHA-256 as the PRF.
///
/// Derives `num_bytes` of key material from `key_material` and a `label`.
///
/// Counter format: 4-byte big-endian counter starting at 1, prepended to `label || 0x00 || context`.
/// See NIST SP 800-108r1, Section 4.1.
use crate::hmac::hmac_sha256;

/// Derive `num_bytes` of pseudorandom output using SP 800-108r1 counter mode.
///
/// # Arguments
/// * `key_material` — The KDK (key derivation key), typically 32 bytes.
/// * `label`        — A purpose string encoded as bytes (e.g. `b"election nonce"`).
/// * `context`      — Additional context bytes (can be empty).
/// * `num_bytes`    — Number of output bytes desired (must be ≤ `255 * 32`).
pub fn kdf_hmac_sha256(
    key_material: &[u8],
    label: &[u8],
    context: &[u8],
    num_bytes: usize,
) -> Vec<u8> {
    assert!(
        num_bytes <= 255 * 32,
        "kdf_hmac_sha256: requested output ({num_bytes} bytes) exceeds maximum (8160 bytes)"
    );
    let num_blocks = num_bytes.div_ceil(32);
    let mut output = Vec::with_capacity(num_blocks * 32);

    for counter in 1u32..=(num_blocks as u32) {
        // PRF input: counter (4 bytes BE) || label || 0x00 || context
        let mut prf_input = Vec::with_capacity(4 + label.len() + 1 + context.len());
        prf_input.extend_from_slice(&counter.to_be_bytes());
        prf_input.extend_from_slice(label);
        prf_input.push(0x00);
        prf_input.extend_from_slice(context);

        let block = hmac_sha256(key_material, &prf_input);
        output.extend_from_slice(&block);
    }

    output.truncate(num_bytes);
    output
}

/// Derive a single 32-byte key from `key_material` and `label`.
pub fn kdf_key(key_material: &[u8], label: &[u8], context: &[u8]) -> [u8; 32] {
    let out = kdf_hmac_sha256(key_material, label, context, 32);
    out.try_into().expect("kdf output is exactly 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_output() {
        let k = [0u8; 32];
        let out1 = kdf_hmac_sha256(&k, b"test", b"ctx", 64);
        let out2 = kdf_hmac_sha256(&k, b"test", b"ctx", 64);
        assert_eq!(out1, out2);
    }

    #[test]
    fn different_labels_different_output() {
        let k = [0u8; 32];
        let out1 = kdf_hmac_sha256(&k, b"label1", b"", 32);
        let out2 = kdf_hmac_sha256(&k, b"label2", b"", 32);
        assert_ne!(out1, out2);
    }

    #[test]
    fn output_length_respects_request() {
        let k = [0u8; 32];
        for len in [1, 16, 32, 33, 64, 100] {
            let out = kdf_hmac_sha256(&k, b"test", b"", len);
            assert_eq!(out.len(), len, "expected {len} bytes");
        }
    }

    #[test]
    fn single_block_matches_kdf_key() {
        let k = [0xABu8; 32];
        let out_vec = kdf_hmac_sha256(&k, b"key", b"ctx", 32);
        let out_arr = kdf_key(&k, b"key", b"ctx");
        assert_eq!(&out_vec[..], &out_arr[..]);
    }
}
