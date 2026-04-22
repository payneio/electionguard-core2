use crate::error::Result;
use crate::group::ElementModQ;
use crate::group::constants::{
    EG_DS_CONTEST_DATA_NONCE, EG_DS_ENCRYPTION_NONCE, EG_DS_SELECTION_ENC_ID,
};
use crate::hash::{hash_elems_v21, HashableValue};

// ── Nonces ────────────────────────────────────────────────────────────────────

/// Deterministic nonce sequence generator.
///
/// Given a `seed` (and optional `header` bytes), produces an indexed sequence
/// of nonces by hashing:
/// ```text
/// nonce[i] = H(seed; header || i)
/// ```
/// where `i` is serialized as a 4-byte big-endian u64 (low 32 bits per spec).
pub struct Nonces {
    seed: ElementModQ,
    header: Vec<u8>,
    counter: u64,
}

impl Nonces {
    /// Create a nonce generator with the given seed.
    pub fn new(seed: &ElementModQ) -> Self {
        Self { seed: seed.clone(), header: Vec::new(), counter: 0 }
    }

    /// Create a nonce generator with a seed and a header prefix.
    pub fn with_header(seed: &ElementModQ, header: &[u8]) -> Self {
        Self { seed: seed.clone(), header: header.to_vec(), counter: 0 }
    }

    /// Get the nonce at index `item` (does not advance the internal counter).
    pub fn get(&self, item: u64) -> Result<ElementModQ> {
        // Domain separator 0x00 is used generically here; the seed uniquely
        // identifies the nonce sequence, so no per-sequence domain separator
        // is needed beyond what the caller provides as the seed.
        //
        // H(seed; 0x00, header_bytes, item_as_u64)
        if self.header.is_empty() {
            hash_elems_v21(&self.seed, 0x00, &[HashableValue::U64(item)])
        } else {
            hash_elems_v21(
                &self.seed,
                0x00,
                &[HashableValue::Bytes(&self.header), HashableValue::U64(item)],
            )
        }
    }

    /// Get the nonce at index `item` with an additional string header prepended.
    pub fn get_with_header(&self, item: u64, header: &str) -> Result<ElementModQ> {
        hash_elems_v21(
            &self.seed,
            0x00,
            &[HashableValue::Str(header), HashableValue::U64(item)],
        )
    }

    /// Get a contiguous range of nonces `[start, start + count)`.
    pub fn get_range(&self, start: u64, count: u64) -> Result<Vec<ElementModQ>> {
        (start..start + count).map(|i| self.get(i)).collect()
    }

    /// Get the nonce at the current counter position and advance the counter.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<ElementModQ> {
        let n = self.get(self.counter)?;
        self.counter += 1;
        Ok(n)
    }

    /// Reset the counter to zero.
    pub fn reset(&mut self) {
        self.counter = 0;
    }

    /// Current counter position.
    pub fn position(&self) -> u64 {
        self.counter
    }
}

// ── v2.1 nonce derivation functions ─────────────────────────────────────────

/// v2.1: `H_I = H(H_E; 0x20, ballot_id)` — selection encryption identifier.
///
/// Used as a per-ballot context value that is hashed into all per-selection
/// nonces and confirmation codes.
pub fn compute_selection_encryption_id(
    extended_hash: &ElementModQ,
    ballot_id: &ElementModQ,
) -> Result<ElementModQ> {
    hash_elems_v21(
        extended_hash,
        EG_DS_SELECTION_ENC_ID,
        &[HashableValue::ModQ(ballot_id)],
    )
}

/// v2.1: `ξ_{i,j} = H(H_I; 0x21, i, j, ξ_B)` — per-selection encryption nonce.
///
/// # Arguments
/// * `selection_enc_id` — H_I (ballot-level selection encryption identifier)
/// * `contest_index`    — 1-based index of the contest
/// * `selection_index`  — 1-based index of the selection within the contest
/// * `ballot_nonce`     — ξ_B, the per-ballot master nonce
pub fn derive_selection_nonce(
    selection_enc_id: &ElementModQ,
    contest_index: u64,
    selection_index: u64,
    ballot_nonce: &ElementModQ,
) -> Result<ElementModQ> {
    hash_elems_v21(
        selection_enc_id,
        EG_DS_ENCRYPTION_NONCE,
        &[
            HashableValue::U64(contest_index),
            HashableValue::U64(selection_index),
            HashableValue::ModQ(ballot_nonce),
        ],
    )
}

/// v2.1: `ξ = H(H_I; 0x25, ind_c, ξ_B)` — contest data encryption nonce.
///
/// # Arguments
/// * `selection_enc_id` — H_I (ballot-level selection encryption identifier)
/// * `contest_index`    — 1-based index of the contest
/// * `ballot_nonce`     — ξ_B, the per-ballot master nonce
pub fn derive_contest_data_nonce(
    selection_enc_id: &ElementModQ,
    contest_index: u64,
    ballot_nonce: &ElementModQ,
) -> Result<ElementModQ> {
    hash_elems_v21(
        selection_enc_id,
        EG_DS_CONTEST_DATA_NONCE,
        &[
            HashableValue::U64(contest_index),
            HashableValue::ModQ(ballot_nonce),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_deterministic() {
        let seed = ElementModQ::from_u64(12345);
        let gen = Nonces::new(&seed);
        let a = gen.get(0).unwrap();
        let b = gen.get(0).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn nonces_distinct_indices() {
        let seed = ElementModQ::from_u64(99);
        let gen = Nonces::new(&seed);
        let n0 = gen.get(0).unwrap();
        let n1 = gen.get(1).unwrap();
        let n2 = gen.get(2).unwrap();
        assert_ne!(n0, n1);
        assert_ne!(n1, n2);
    }

    #[test]
    fn nonces_next_advances_counter() {
        let seed = ElementModQ::from_u64(1);
        let mut gen = Nonces::new(&seed);
        let n0_direct = gen.get(0).unwrap();
        let n0_next = gen.next().unwrap();
        assert_eq!(n0_direct, n0_next);
        let n1_direct = gen.get(1).unwrap();
        let n1_next = gen.next().unwrap();
        assert_eq!(n1_direct, n1_next);
        assert_eq!(gen.position(), 2);
    }

    #[test]
    fn nonces_range() {
        let seed = ElementModQ::from_u64(7);
        let gen = Nonces::new(&seed);
        let range = gen.get_range(10, 5).unwrap();
        assert_eq!(range.len(), 5);
        for i in 0..5u64 {
            assert_eq!(range[i as usize], gen.get(10 + i).unwrap());
        }
    }

    #[test]
    fn selection_encryption_id_deterministic() {
        let h_e = ElementModQ::from_u64(1);
        let ballot_id = ElementModQ::from_u64(42);
        let id1 = compute_selection_encryption_id(&h_e, &ballot_id).unwrap();
        let id2 = compute_selection_encryption_id(&h_e, &ballot_id).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn selection_nonce_uses_all_inputs() {
        let h_i = ElementModQ::from_u64(100);
        let nonce = ElementModQ::from_u64(7);
        let n1 = derive_selection_nonce(&h_i, 1, 1, &nonce).unwrap();
        let n2 = derive_selection_nonce(&h_i, 1, 2, &nonce).unwrap();
        let n3 = derive_selection_nonce(&h_i, 2, 1, &nonce).unwrap();
        assert_ne!(n1, n2, "different selection index must give different nonce");
        assert_ne!(n1, n3, "different contest index must give different nonce");
    }

    #[test]
    fn contest_data_nonce_deterministic() {
        let h_i = ElementModQ::from_u64(100);
        let nonce = ElementModQ::from_u64(7);
        let d1 = derive_contest_data_nonce(&h_i, 1, &nonce).unwrap();
        let d2 = derive_contest_data_nonce(&h_i, 1, &nonce).unwrap();
        assert_eq!(d1, d2);
        let d3 = derive_contest_data_nonce(&h_i, 2, &nonce).unwrap();
        assert_ne!(d1, d3, "different contest index must give different nonce");
    }
}
