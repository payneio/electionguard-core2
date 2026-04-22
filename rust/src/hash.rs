use crypto_bigint::{Encoding, U256};

use crate::error::{Error, Result};
use crate::group::{ElementModP, ElementModQ};
use crate::hmac::hmac_sha256;
use crate::group::constants::Q_VALUE;

// ── HashableValue ────────────────────────────────────────────────────────────

/// A value that can be serialized into the v2.1 HMAC hash function.
///
/// Serialization rules per the v2.1 spec:
/// - `ModP`  → 512 bytes big-endian
/// - `ModQ`  → 32 bytes big-endian
/// - `U64`   → 4 bytes big-endian (low 32 bits, i.e. truncated to u32)
/// - `Str`   → 4-byte BE length prefix followed by UTF-8 bytes
/// - `Bytes` → 4-byte BE length prefix followed by raw bytes
/// - `Null`  → four zero bytes `[0x00, 0x00, 0x00, 0x00]`
/// - `Seq`   → each element serialized in order (no extra framing)
pub enum HashableValue<'a> {
    /// An element of Z*_P (4096-bit group element).
    ModP(&'a ElementModP),
    /// An element of Z_Q (256-bit scalar).
    ModQ(&'a ElementModQ),
    /// An unsigned 64-bit integer serialized as 4 big-endian bytes.
    U64(u64),
    /// A UTF-8 string, length-prefixed with 4 big-endian bytes.
    Str(&'a str),
    /// Raw bytes, length-prefixed with 4 big-endian bytes.
    Bytes(&'a [u8]),
    /// Absence / null — serializes as four zero bytes.
    Null,
    /// A sequence of hashable values (each serialized in order).
    Seq(Vec<HashableValue<'a>>),
}

// ── From conversions ──────────────────────────────────────────────────────────

impl<'a> From<&'a ElementModP> for HashableValue<'a> {
    fn from(v: &'a ElementModP) -> Self {
        HashableValue::ModP(v)
    }
}

impl<'a> From<&'a ElementModQ> for HashableValue<'a> {
    fn from(v: &'a ElementModQ) -> Self {
        HashableValue::ModQ(v)
    }
}

impl<'a> From<u64> for HashableValue<'a> {
    fn from(v: u64) -> Self {
        HashableValue::U64(v)
    }
}

impl<'a> From<&'a str> for HashableValue<'a> {
    fn from(v: &'a str) -> Self {
        HashableValue::Str(v)
    }
}

impl<'a> From<&'a [u8]> for HashableValue<'a> {
    fn from(v: &'a [u8]) -> Self {
        HashableValue::Bytes(v)
    }
}

// ── CryptoHashable trait ──────────────────────────────────────────────────────

/// Trait for types that can produce a cryptographic hash.
///
/// Rust equivalent of the C++ `CryptoHashable` interface.
/// The `crypto_hash()` implementation should produce a deterministic
/// `ElementModQ` that uniquely identifies the type's content.
pub trait CryptoHashable {
    fn crypto_hash(&self) -> Result<ElementModQ>;
}

// ── Internal serializer ───────────────────────────────────────────────────────

/// Serialize a single `HashableValue` into `buf`.
fn serialize_value(val: &HashableValue<'_>, buf: &mut Vec<u8>) {
    match val {
        HashableValue::ModP(p) => {
            buf.extend_from_slice(&p.to_bytes_be());
        }
        HashableValue::ModQ(q) => {
            buf.extend_from_slice(&q.to_bytes_be());
        }
        HashableValue::U64(v) => {
            // Truncate to u32 per the C++ ElectionGuard spec.
            let low32 = (*v & 0xFFFF_FFFF) as u32;
            buf.extend_from_slice(&low32.to_be_bytes());
        }
        HashableValue::Str(s) => {
            let bytes = s.as_bytes();
            let len = bytes.len() as u32;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(bytes);
        }
        HashableValue::Bytes(b) => {
            let len = b.len() as u32;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(b);
        }
        HashableValue::Null => {
            buf.extend_from_slice(&[0x00u8; 4]);
        }
        HashableValue::Seq(items) => {
            for item in items {
                serialize_value(item, buf);
            }
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// v2.1 HMAC-based hash function.
///
/// Computes `H(key; domain_sep || serialize(args...))` and returns the result
/// reduced mod Q as an `ElementModQ`.
///
/// # Message construction
/// ```text
/// message = [domain_separator_byte] || enc(arg[0]) || enc(arg[1]) || ...
/// output  = HMAC-SHA-256(key.to_bytes_be(), message)  reduced mod Q
/// ```
pub fn hash_elems_v21(
    key: &ElementModQ,
    domain_separator: u8,
    args: &[HashableValue<'_>],
) -> Result<ElementModQ> {
    hash_elems_v21_raw(&key.to_bytes_be(), domain_separator, args)
}

/// Identical to `hash_elems_v21` — provided for API symmetry with the C++ SDK.
pub fn hash_elems_v21_q(
    key: &ElementModQ,
    domain_separator: u8,
    args: &[HashableValue<'_>],
) -> Result<ElementModQ> {
    hash_elems_v21(key, domain_separator, args)
}

/// v2.1 hash with an explicit 32-byte raw key (e.g. all-zero key for `H_P`).
pub fn hash_elems_v21_raw(
    key: &[u8; 32],
    domain_separator: u8,
    args: &[HashableValue<'_>],
) -> Result<ElementModQ> {
    // Build the HMAC message.
    let mut message = Vec::with_capacity(1 + args.len() * 32);
    message.push(domain_separator);
    for arg in args {
        serialize_value(arg, &mut message);
    }

    // HMAC-SHA-256(key, message)
    let digest = hmac_sha256(key, &message);

    // Interpret 32-byte digest as U256 (big-endian) and reduce mod Q.
    let raw = U256::from_be_bytes(digest);
    let q_nz = crypto_bigint::NonZero::new(Q_VALUE)
        .expect("Q_VALUE is a known nonzero prime");
    let reduced = raw.rem(&q_nz);

    ElementModQ::new(reduced).map_err(|e| Error::Arithmetic(format!("hash reduction: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_deterministic() {
        let key = ElementModQ::from_u64(1);
        let h1 = hash_elems_v21(&key, 0x00, &[HashableValue::U64(42)]).unwrap();
        let h2 = hash_elems_v21(&key, 0x00, &[HashableValue::U64(42)]).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_domain_sep_changes_output() {
        let key = ElementModQ::from_u64(1);
        let h1 = hash_elems_v21(&key, 0x00, &[HashableValue::U64(1)]).unwrap();
        let h2 = hash_elems_v21(&key, 0x01, &[HashableValue::U64(1)]).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_key_changes_output() {
        let k1 = ElementModQ::from_u64(1);
        let k2 = ElementModQ::from_u64(2);
        let h1 = hash_elems_v21(&k1, 0x00, &[HashableValue::U64(1)]).unwrap();
        let h2 = hash_elems_v21(&k2, 0x00, &[HashableValue::U64(1)]).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_null_value() {
        let key = ElementModQ::from_u64(1);
        let h = hash_elems_v21(&key, 0x00, &[HashableValue::Null]).unwrap();
        // Just check it doesn't panic and returns a valid Q element.
        assert!(*h.value() < crate::group::constants::Q_VALUE);
    }

    #[test]
    fn hash_mod_p_value() {
        let key = ElementModQ::from_u64(7);
        let g = ElementModP::g();
        let h = hash_elems_v21(&key, 0x20, &[HashableValue::ModP(g)]).unwrap();
        assert!(*h.value() < crate::group::constants::Q_VALUE);
    }

    #[test]
    fn hash_raw_key_zeroes() {
        let key = [0u8; 32];
        let h = hash_elems_v21_raw(&key, 0x00, &[HashableValue::Str("v2.1")]).unwrap();
        // Should not panic; value must be in [0, Q).
        assert!(*h.value() < crate::group::constants::Q_VALUE);
    }
}
