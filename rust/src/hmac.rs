use hmac::{Hmac, Mac};
use sha2::Sha256;

/// The fixed HMAC key size (SHA-256 block size = 64 bytes for HMAC, but EG uses 32).
pub const HMAC_KEY_SIZE: usize = 32;
/// HMAC-SHA-256 output length (bytes).
pub const HMAC_OUTPUT_SIZE: usize = 32;

/// Compute `HMAC-SHA-256(key, message)` and return the 32-byte digest.
///
/// This is the low-level primitive used throughout ElectionGuard v2.1.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; HMAC_OUTPUT_SIZE] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA-256 accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Compute `HMAC-SHA-256(key, message)` and return the result as a `Vec<u8>`.
pub fn hmac_sha256_vec(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac_sha256(key, message).to_vec()
}

/// Verify a MAC tag in constant time.
///
/// Returns `true` iff `HMAC-SHA-256(key, message) == expected`.
pub fn hmac_sha256_verify(key: &[u8], message: &[u8], expected: &[u8]) -> bool {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA-256 accepts any key length");
    mac.update(message);
    mac.verify_slice(expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from RFC 4231 — test case 1.
    #[test]
    fn rfc4231_test_case_1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected = hex::decode(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        )
        .unwrap();
        let result = hmac_sha256(&key, data);
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn verify_ok() {
        let key = b"test-key";
        let msg = b"hello world";
        let tag = hmac_sha256(key, msg);
        assert!(hmac_sha256_verify(key, msg, &tag));
    }

    #[test]
    fn verify_fail_wrong_msg() {
        let key = b"test-key";
        let tag = hmac_sha256(key, b"hello world");
        assert!(!hmac_sha256_verify(key, b"hello WORLD", &tag));
    }
}
