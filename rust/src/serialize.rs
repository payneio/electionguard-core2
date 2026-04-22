use crypto_bigint::{Encoding, U256, U4096};
use serde::{Deserializer, Serializer};

/// Serde module for serializing U4096 as lowercase hex string (1024 chars).
pub mod u4096_hex {
    use super::*;
    use serde::Deserialize;

    // Non-generic helper so tarpaulin can instrument the body in release mode.
    #[inline(never)]
    fn encode_u4096(value: &U4096) -> String {
        hex::encode(value.to_be_bytes().as_ref())
    }

    // Non-generic helper so tarpaulin can instrument the body in release mode.
    #[inline(never)]
    fn decode_u4096(hex_str: &str) -> Result<U4096, String> {
        if hex_str.len() != 1024 {
            return Err(format!("expected 1024 hex chars for U4096, got {}", hex_str.len()));
        }
        let mut bytes = [0u8; 512];
        hex::decode_to_slice(hex_str, &mut bytes).map_err(|e| format!("hex decode error: {e}"))?;
        Ok(U4096::from_be_bytes(bytes))
    }

    pub fn serialize<S: Serializer>(value: &U4096, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode_u4096(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U4096, D::Error> {
        let hex_str = String::deserialize(d)?;
        decode_u4096(&hex_str).map_err(serde::de::Error::custom)
    }
}

/// Serde module for serializing U256 as lowercase hex string (64 chars).
pub mod u256_hex {
    use super::*;
    use serde::Deserialize;

    // Non-generic helper so tarpaulin can instrument the body in release mode.
    #[inline(never)]
    fn encode_u256(value: &U256) -> String {
        hex::encode(value.to_be_bytes().as_ref())
    }

    // Non-generic helper so tarpaulin can instrument the body in release mode.
    #[inline(never)]
    fn decode_u256(hex_str: &str) -> Result<U256, String> {
        if hex_str.len() != 64 {
            return Err(format!("expected 64 hex chars for U256, got {}", hex_str.len()));
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut bytes).map_err(|e| format!("hex decode error: {e}"))?;
        Ok(U256::from_be_bytes(bytes))
    }

    pub fn serialize<S: Serializer>(value: &U256, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode_u256(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U256, D::Error> {
        let hex_str = String::deserialize(d)?;
        decode_u256(&hex_str).map_err(serde::de::Error::custom)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────
// Inline tests call the helper functions directly so tarpaulin can instrument
// each statement.  The helpers are `#[inline(never)]` so that release-mode
// optimisations do not fold them away before the coverage instrumentation runs.
#[cfg(test)]
mod tests_u4096 {
    use super::u4096_hex::{deserialize as de4096, serialize as ser4096};
    use crypto_bigint::U4096;

    /// Round-trip: serialize → deserialize must be the identity.
    #[test]
    fn u4096_round_trip() {
        let original = U4096::from_u64(0xDEAD_BEEF_u64);
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::new(&mut buf);
        ser4096(&original, &mut ser).expect("u4096 serialize must succeed");
        let json_str = String::from_utf8(buf).unwrap();
        // Exactly 1024 hex chars + 2 JSON quotes.
        assert_eq!(json_str.len(), 1026, "serialized length must be 1026");
        let mut de = serde_json::Deserializer::from_str(&json_str);
        let recovered = de4096(&mut de).expect("u4096 deserialize must succeed");
        assert_eq!(original, recovered, "round-trip must be lossless");
    }

    /// Deserialize error – wrong length.
    #[test]
    fn u4096_wrong_length_fails() {
        let short = "\"aabbcc\"";
        let mut de = serde_json::Deserializer::from_str(short);
        let result = de4096(&mut de);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("expected 1024 hex chars"));
    }

    /// Deserialize error – invalid hex characters.
    #[test]
    fn u4096_invalid_hex_fails() {
        let bad = format!("\"z{}\"", "0".repeat(1023));
        let mut de = serde_json::Deserializer::from_str(&bad);
        let result = de4096(&mut de);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("hex decode error") || msg.contains("invalid"));
    }
}

#[cfg(test)]
mod tests_u256 {
    use super::u256_hex::{deserialize as de256, serialize as ser256};
    use crypto_bigint::U256;

    /// Round-trip: serialize → deserialize must be the identity.
    #[test]
    fn u256_round_trip() {
        let original = U256::from_u64(0xCAFE_BABE_u64);
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::new(&mut buf);
        ser256(&original, &mut ser).expect("u256 serialize must succeed");
        let json_str = String::from_utf8(buf).unwrap();
        // Exactly 64 hex chars + 2 JSON quotes.
        assert_eq!(json_str.len(), 66, "serialized length must be 66");
        let mut de = serde_json::Deserializer::from_str(&json_str);
        let recovered = de256(&mut de).expect("u256 deserialize must succeed");
        assert_eq!(original, recovered, "round-trip must be lossless");
    }

    /// Deserialize error – wrong length.
    #[test]
    fn u256_wrong_length_fails() {
        let short = "\"aabb\"";
        let mut de = serde_json::Deserializer::from_str(short);
        let result = de256(&mut de);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("expected 64 hex chars"));
    }

    /// Deserialize error – invalid hex characters.
    #[test]
    fn u256_invalid_hex_fails() {
        let bad = format!("\"z{}\"", "0".repeat(63));
        let mut de = serde_json::Deserializer::from_str(&bad);
        let result = de256(&mut de);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("hex decode error") || msg.contains("invalid"));
    }
}
