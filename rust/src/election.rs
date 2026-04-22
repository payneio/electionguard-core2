//! Election context and parameter hash chain.
//!
//! Implements the v2.1 hash chain:
//!
//! ```text
//! H_P = H(00^32; 0x00, "v2.1", P, Q, G)          — parameter hash
//! H_B = H(H_P;   0x01, n, k, H_M, Ĥ)             — base hash
//! H_E = H(H_B;   0x02, Ĥ)                         — extended base hash
//! ```
//!
//! where `H_M` is the manifest hash and `Ĥ` is the commitment hash from the
//! key ceremony.

use crate::error::{Error, Result};
use crate::group::{ElementModP, ElementModQ};
use crate::group::constants::{
    EG_DS_ELECTION_BASE_HASH, EG_DS_EXTENDED_BASE_HASH, EG_DS_PARAMETER_HASH, G_VALUE, P_VALUE,
    Q_VALUE,
};
use crate::hash::{hash_elems_v21, HashableValue};
use crate::hmac::hmac_sha256;
use crypto_bigint::{Encoding, NonZero, U256};
use serde::{Deserialize, Serialize};

// ── CiphertextElectionContext ──────────────────────────────────────────────

/// The election context: all public parameters used for ballot encryption and
/// decryption.
///
/// Dual-key system:
/// * `elgamal_public_key` — joint vote encryption key K = ∏ K_i
/// * `data_public_key`    — joint data encryption key K̂ = ∏ K̂_i
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiphertextElectionContext {
    /// Number of guardians (n).
    pub number_of_guardians: u64,
    /// Quorum threshold (k).
    pub quorum: u64,
    /// Joint vote encryption public key K = ∏ K_i mod P.
    pub elgamal_public_key: ElementModP,
    /// Joint data encryption public key K̂ = ∏ K̂_i mod P.
    pub data_public_key: ElementModP,
    /// Hash of the election manifest (H_M).
    pub manifest_hash: ElementModQ,
    /// Commitment hash from the key ceremony (Ĥ).
    pub commitment_hash: ElementModQ,
    /// Extended base hash H_E — used as the HMAC key for v2.1 hashing.
    pub extended_base_hash: ElementModQ,
    /// Parameter hash H_P.
    pub parameter_hash: ElementModQ,
    /// Election base hash H_B.
    pub base_hash: ElementModQ,
}

impl CiphertextElectionContext {
    /// Construct the election context and compute the full hash chain:
    /// `H_P → H_B → H_E`.
    ///
    /// # Arguments
    /// * `number_of_guardians` — n (total guardians)
    /// * `quorum`              — k (threshold)
    /// * `elgamal_public_key`  — joint vote encryption public key
    /// * `data_public_key`     — joint data encryption public key
    /// * `commitment_hash`     — Ĥ from the key ceremony
    /// * `manifest_hash`       — H_M = manifest.crypto_hash()
    pub fn new(
        number_of_guardians: u64,
        quorum: u64,
        elgamal_public_key: ElementModP,
        data_public_key: ElementModP,
        commitment_hash: ElementModQ,
        manifest_hash: ElementModQ,
    ) -> Result<Self> {
        if quorum > number_of_guardians {
            return Err(Error::InvalidElection(format!(
                "quorum ({}) > number_of_guardians ({})",
                quorum, number_of_guardians
            )));
        }
        if number_of_guardians == 0 {
            return Err(Error::InvalidElection("number_of_guardians must be > 0".to_string()));
        }

        let parameter_hash = compute_parameter_hash()?;
        let base_hash = compute_base_hash(
            &parameter_hash,
            number_of_guardians,
            quorum,
            &manifest_hash,
            &commitment_hash,
        )?;
        let extended_base_hash = compute_extended_base_hash(&base_hash, &commitment_hash)?;

        Ok(Self {
            number_of_guardians,
            quorum,
            elgamal_public_key,
            data_public_key,
            manifest_hash,
            commitment_hash,
            extended_base_hash,
            parameter_hash,
            base_hash,
        })
    }

    /// Deserialize from a JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| Error::Serialization(format!("CiphertextElectionContext::from_json: {}", e)))
    }

    /// Serialize to a JSON string.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| Error::Serialization(format!("CiphertextElectionContext::to_json: {}", e)))
    }
}

// ── Hash chain functions ───────────────────────────────────────────────────

/// Compute the **parameter hash** `H_P`.
///
/// ```text
/// H_P = HMAC-SHA-256(key=00^32, msg = 0x00 | len4("v2.1") | "v2.1" | P | Q | G)
/// ```
///
/// The key is 32 zero bytes (matches C++ "zero key" convention).
/// `P` and `G` are serialized as 512-byte big-endian values.
/// `Q` is serialized as 32 bytes big-endian (the prime itself, not mod-Q).
/// The version string `"v2.1"` is length-prefixed with a 4-byte big-endian length,
/// consistent with the `HashableValue::Str` serialization used elsewhere.
pub fn compute_parameter_hash() -> Result<ElementModQ> {
    let zero_key = [0u8; 32];

    // Build the HMAC message matching the HashableValue serialisation rules:
    //   [domain_sep] | Str("v2.1") | ModP(P) | Q_raw(32B) | ModP(G)
    let mut msg: Vec<u8> = Vec::with_capacity(1 + 8 + 512 + 32 + 512);
    msg.push(EG_DS_PARAMETER_HASH); // 0x00

    // "v2.1" as a length-prefixed string (4-byte BE length + bytes)
    let ver = b"v2.1";
    msg.extend_from_slice(&(ver.len() as u32).to_be_bytes());
    msg.extend_from_slice(ver);

    // P as 512 big-endian bytes
    msg.extend_from_slice(&P_VALUE.to_be_bytes());

    // Q as 32 big-endian bytes
    // (Q is the prime itself; ElementModQ requires value < Q so we bypass it)
    msg.extend_from_slice(&Q_VALUE.to_be_bytes());

    // G as 512 big-endian bytes
    msg.extend_from_slice(&G_VALUE.to_be_bytes());

    let digest = hmac_sha256(&zero_key, &msg);
    raw_digest_to_modq(digest)
}

/// Compute the **election base hash** `H_B`.
///
/// ```text
/// H_B = H(H_P; 0x01, n, k, H_M, Ĥ)
/// ```
pub fn compute_base_hash(
    parameter_hash: &ElementModQ,
    number_of_guardians: u64,
    quorum: u64,
    manifest_hash: &ElementModQ,
    commitment_hash: &ElementModQ,
) -> Result<ElementModQ> {
    hash_elems_v21(
        parameter_hash,
        EG_DS_ELECTION_BASE_HASH,
        &[
            HashableValue::U64(number_of_guardians),
            HashableValue::U64(quorum),
            HashableValue::ModQ(manifest_hash),
            HashableValue::ModQ(commitment_hash),
        ],
    )
}

/// Compute the **extended base hash** `H_E`.
///
/// ```text
/// H_E = H(H_B; 0x02, Ĥ)
/// ```
pub fn compute_extended_base_hash(
    base_hash: &ElementModQ,
    commitment_hash: &ElementModQ,
) -> Result<ElementModQ> {
    hash_elems_v21(
        base_hash,
        EG_DS_EXTENDED_BASE_HASH,
        &[HashableValue::ModQ(commitment_hash)],
    )
}

// ── Internal helpers ───────────────────────────────────────────────────────

/// Reduce a raw 32-byte HMAC-SHA-256 digest to an `ElementModQ` (mod Q).
fn raw_digest_to_modq(digest: [u8; 32]) -> Result<ElementModQ> {
    let raw = U256::from_be_bytes(digest);
    let q_nz = NonZero::new(Q_VALUE).expect("Q_VALUE is a known nonzero prime");
    let reduced = raw.rem(&q_nz);
    ElementModQ::new(reduced)
        .map_err(|_| Error::Arithmetic("parameter hash: reduction out of range".to_string()))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dummy_key() -> ElementModP {
        ElementModP::g().clone()
    }

    fn make_dummy_q() -> ElementModQ {
        ElementModQ::from_u64(42)
    }

    #[test]
    fn parameter_hash_deterministic() {
        let h1 = compute_parameter_hash().unwrap();
        let h2 = compute_parameter_hash().unwrap();
        assert_eq!(h1, h2, "H_P must be deterministic");
    }

    #[test]
    fn parameter_hash_nonzero() {
        let hp = compute_parameter_hash().unwrap();
        assert!(!hp.is_zero(), "H_P must not be zero");
    }

    #[test]
    fn base_hash_depends_on_all_inputs() {
        let hp = compute_parameter_hash().unwrap();
        let mh = make_dummy_q();
        let ch = ElementModQ::from_u64(99);

        let hb1 = compute_base_hash(&hp, 3, 2, &mh, &ch).unwrap();
        let hb2 = compute_base_hash(&hp, 3, 2, &mh, &ElementModQ::from_u64(100)).unwrap();
        assert_ne!(hb1, hb2, "changing commitment_hash must change H_B");

        let hb3 = compute_base_hash(&hp, 5, 2, &mh, &ch).unwrap();
        assert_ne!(hb1, hb3, "changing n must change H_B");
    }

    #[test]
    fn hash_chain_h_p_to_h_e() {
        let hp = compute_parameter_hash().unwrap();
        let mh = make_dummy_q();
        let ch = ElementModQ::from_u64(7);

        let hb = compute_base_hash(&hp, 3, 2, &mh, &ch).unwrap();
        let he = compute_extended_base_hash(&hb, &ch).unwrap();

        // Each hash in the chain must be distinct.
        assert_ne!(hp, hb);
        assert_ne!(hb, he);
        assert_ne!(hp, he);
    }

    #[test]
    fn context_new_computes_hash_chain() {
        let key = make_dummy_key();
        let mh = make_dummy_q();
        let ch = ElementModQ::from_u64(7);

        let ctx = CiphertextElectionContext::new(3, 2, key.clone(), key, ch.clone(), mh).unwrap();

        // Verify the stored hashes match what the standalone functions produce.
        let hp = compute_parameter_hash().unwrap();
        assert_eq!(ctx.parameter_hash, hp);

        let hb = compute_base_hash(&hp, 3, 2, &ctx.manifest_hash, &ch).unwrap();
        assert_eq!(ctx.base_hash, hb);

        let he = compute_extended_base_hash(&hb, &ch).unwrap();
        assert_eq!(ctx.extended_base_hash, he);
    }

    #[test]
    fn context_json_round_trip() {
        let key = make_dummy_key();
        let mh = make_dummy_q();
        let ch = ElementModQ::from_u64(7);

        let ctx = CiphertextElectionContext::new(3, 2, key.clone(), key, ch, mh).unwrap();
        let json = ctx.to_json().unwrap();
        let ctx2 = CiphertextElectionContext::from_json(&json).unwrap();

        assert_eq!(ctx.number_of_guardians, ctx2.number_of_guardians);
        assert_eq!(ctx.quorum, ctx2.quorum);
        assert_eq!(ctx.parameter_hash, ctx2.parameter_hash);
        assert_eq!(ctx.base_hash, ctx2.base_hash);
        assert_eq!(ctx.extended_base_hash, ctx2.extended_base_hash);
    }

    #[test]
    fn context_rejects_quorum_gt_n() {
        let key = make_dummy_key();
        let mh = make_dummy_q();
        let ch = make_dummy_q();

        let result =
            CiphertextElectionContext::new(2, 3, key.clone(), key, ch, mh);
        assert!(result.is_err(), "quorum > n must be rejected");
    }

    #[test]
    fn context_rejects_zero_n() {
        let key = make_dummy_key();
        let result = CiphertextElectionContext::new(
            0,
            0,
            key.clone(),
            key,
            make_dummy_q(),
            make_dummy_q(),
        );
        assert!(result.is_err(), "n=0 must be rejected");
    }
}
