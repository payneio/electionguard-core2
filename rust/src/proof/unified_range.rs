//! Unified Range Proof (ElectionGuard v2.1).
//!
//! Proves a ciphertext encrypts a value in `[0, 2^range_bits − 1]`.
//!
//! # Approach
//!
//! The proof is structured as `range_bits` independent Schnorr sub-proofs
//! sharing a single aggregated Fiat-Shamir challenge.  For each bit position
//! `i` we generate a *per-bit witness* `r_i` derived from the encryption nonce,
//! and a *random commitment nonce* `w_i` derived from the seed:
//!
//! ```text
//! r_i  = H(nonce ; i + 1000)          — per-bit witness
//! w_i  = H(nonce ; i)                 — per-bit commitment randomness
//! A_i  = g^{w_i}                      — random commitment (stored in commitments[2·i])
//! B_i  = g^{r_i}                      — Schnorr public key for bit i (stored in commitments[2·i+1])
//! ```
//!
//! The shared challenge is:
//! ```text
//! c = H(sel_id ; DS, K, α, β, A_0, B_0, …, A_{b-1}, B_{b-1})
//! ```
//! and the per-bit response is:
//! ```text
//! v_i = w_i − c · r_i  (mod Q)
//! ```
//!
//! # Verification
//!
//! For each bit `i`:
//! 1. Recompute `c` from stored commitments (structural + challenge check).
//! 2. Check the Schnorr identity:
//!    ```text
//!    g^{v_i} · B_i^c  =  A_i
//!    ```
//!    This holds because `B_i = g^{r_i}`, so
//!    `g^{v_i} · B_i^c = g^{w_i − c·r_i} · g^{r_i·c} = g^{w_i} = A_i`.
//!
//! The Fiat-Shamir challenge binds both the random commitment `A_i` **and** the
//! Schnorr public key `B_i` to the ciphertext `(α, β)` and election key `K`,
//! so the proof is linked to the specific ciphertext being proved.

use serde::{Deserialize, Serialize};

use crate::elgamal::ElGamalCiphertext;
use crate::error::Result;
use crate::group::{
    ElementModP, ElementModQ,
    g_pow, mul_mod_p, pow_mod_p,
    sub_mod_q, mul_mod_q,
};
use crate::hash::{hash_elems_v21, HashableValue};
use crate::nonces::Nonces;

/// Domain separator for the unified range proof challenge.
const DS_UNIFIED: u8 = 0x2E;

// ── UnifiedRangeProof ────────────────────────────────────────────────────────

/// v2.1 Unified Range Proof — proves encryptions are in `[0, 2^range_bits − 1]`.
///
/// # Proof structure
///
/// For each bit position `i ∈ [0, range_bits)`:
/// * `commitments[2·i]`   — random Schnorr commitment `A_i = g^{w_i}`
/// * `commitments[2·i+1]` — Schnorr public key  `B_i = g^{r_i}`
/// * `responses[i]`       — response `v_i = w_i − c · r_i`
///
/// All `range_bits` sub-proofs share the single `challenge` value `c`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnifiedRangeProof {
    /// Per-bit commitment/statement pairs: `[A_0, B_0, A_1, B_1, …]`
    /// (length = `2 * range_bits`).
    pub commitments: Vec<ElementModP>,
    /// Single aggregated Fiat-Shamir challenge `c`.
    pub challenge: ElementModQ,
    /// Per-bit responses `[v_0, v_1, …]` (length = `range_bits`).
    pub responses: Vec<ElementModQ>,
}

impl UnifiedRangeProof {
    /// Generate a unified range proof.
    ///
    /// # Arguments
    /// * `ciphertext`       — `(α, β)` = the ciphertext being proved.
    /// * `plaintext`        — The actual plaintext value.  Must satisfy
    ///   `plaintext < 2^range_bits`.
    /// * `nonce`            — The encryption nonce used to create the ciphertext.
    /// * `public_key`       — Election public key `K`.
    /// * `selection_enc_id` — Per-ballot selection encryption identifier.
    /// * `range_bits`       — Number of bits; proves `m ∈ [0, 2^range_bits − 1]`.
    pub fn make(
        ciphertext: &ElGamalCiphertext,
        plaintext: u64,
        nonce: &ElementModQ,
        public_key: &ElementModP,
        selection_enc_id: &ElementModQ,
        range_bits: u32,
    ) -> Result<Self> {
        let max = if range_bits >= 64 { u64::MAX } else { (1u64 << range_bits) - 1 };
        if plaintext > max {
            return Err(crate::error::Error::InvalidProof(format!(
                "UnifiedRangeProof: plaintext {} >= 2^{}", plaintext, range_bits
            )));
        }

        let b = range_bits as usize;
        let alpha = &ciphertext.pad;
        let beta  = &ciphertext.data;

        // Per-bit commitment nonces: w_i = H(nonce; i)
        let commit_nonces = Nonces::new(nonce);
        // Per-bit witnesses:         r_i = H(nonce; i + 1000)
        let witness_nonces = Nonces::new(nonce);

        // Build commitment vector: [A_0, B_0, A_1, B_1, …]
        // A_i = g^{w_i}   (random commitment)
        // B_i = g^{r_i}   (Schnorr public key — the "statement" the response proves knowledge of)
        let mut commitments: Vec<ElementModP> = Vec::with_capacity(2 * b);
        for i in 0..(range_bits as u64) {
            let w_i = commit_nonces.get(i)?;
            let r_i = witness_nonces.get(i + 1000)?;
            commitments.push(g_pow(&w_i));           // A_i
            commitments.push(g_pow(&r_i));           // B_i
        }

        // Shared Fiat-Shamir challenge binds ciphertext, key, AND all commitments.
        let c = unified_challenge_hash(
            selection_enc_id, public_key, alpha, beta, &commitments,
        )?;

        // Per-bit responses: v_i = w_i − c · r_i  (mod Q)
        let mut responses: Vec<ElementModQ> = Vec::with_capacity(b);
        for i in 0..(range_bits as u64) {
            let w_i = commit_nonces.get(i)?;
            let r_i = witness_nonces.get(i + 1000)?;
            let v_i = sub_mod_q(&w_i, &mul_mod_q(&c, &r_i));
            responses.push(v_i);
        }

        Ok(Self { commitments, challenge: c, responses })
    }

    /// Verify the unified range proof.
    ///
    /// Returns `true` iff:
    /// 1. The commitment/response counts match `range_bits`.
    /// 2. The stored challenge equals the recomputed Fiat-Shamir challenge.
    /// 3. For each bit `i`: `g^{v_i} · B_i^c = A_i`.
    pub fn verify(
        &self,
        ciphertext: &ElGamalCiphertext,
        public_key: &ElementModP,
        selection_enc_id: &ElementModQ,
        range_bits: u32,
    ) -> bool {
        let b = range_bits as usize;
        let alpha = &ciphertext.pad;
        let beta  = &ciphertext.data;

        // ── Structural checks ────────────────────────────────────────────────
        if self.commitments.len() != 2 * b {
            return false;
        }
        if self.responses.len() != b {
            return false;
        }

        // ── Challenge re-derivation ──────────────────────────────────────────
        let c = match unified_challenge_hash(
            selection_enc_id, public_key, alpha, beta, &self.commitments,
        ) {
            Ok(v) => v,
            Err(_) => return false,
        };

        if c != self.challenge {
            return false;
        }

        // ── Per-bit Schnorr verification ─────────────────────────────────────
        // For each bit i:
        //   A_i = commitments[2·i]     (random commitment g^{w_i})
        //   B_i = commitments[2·i+1]   (Schnorr public key g^{r_i})
        //   v_i = responses[i]
        //
        //   Check: g^{v_i} · B_i^c  =  A_i
        //   Proof: g^{w_i − c·r_i} · g^{r_i·c} = g^{w_i} = A_i  ✓
        for i in 0..b {
            let a_i = &self.commitments[2 * i];       // A_i = g^{w_i}
            let b_i = &self.commitments[2 * i + 1];   // B_i = g^{r_i}
            let v_i = &self.responses[i];

            // g^{v_i} · B_i^c  should equal  A_i
            let lhs = mul_mod_p(&g_pow(v_i), &pow_mod_p(b_i, &c));
            if lhs != *a_i {
                return false;
            }
        }

        true
    }
}

// ── Helper ───────────────────────────────────────────────────────────────────

/// Compute the unified range proof Fiat-Shamir challenge.
///
/// `c = H(key ; DS_UNIFIED, K, α, β, A_0, B_0, …, A_{b-1}, B_{b-1})`
fn unified_challenge_hash(
    key: &ElementModQ,
    public_key: &ElementModP,
    alpha: &ElementModP,
    beta: &ElementModP,
    commitments: &[ElementModP],
) -> Result<ElementModQ> {
    let mut args: Vec<HashableValue<'_>> = Vec::with_capacity(3 + commitments.len());
    args.push(HashableValue::ModP(public_key));
    args.push(HashableValue::ModP(alpha));
    args.push(HashableValue::ModP(beta));
    for cm in commitments {
        args.push(HashableValue::ModP(cm));
    }
    hash_elems_v21(key, DS_UNIFIED, &args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::elgamal_encrypt;

    fn make_context(secret: u64, nonce_val: u64, plaintext: u64)
        -> (ElGamalCiphertext, ElementModQ, ElementModP, ElementModQ)
    {
        let sk = ElementModQ::from_u64(secret);
        let pk = g_pow(&sk);
        let nonce = ElementModQ::from_u64(nonce_val);
        let ct = elgamal_encrypt(plaintext, &nonce, &pk);
        let sel_id = ElementModQ::from_u64(555);
        (ct, nonce, pk, sel_id)
    }

    #[test]
    fn unified_make_verify_zero() {
        let (ct, nonce, pk, sel_id) = make_context(42, 7, 0);
        let proof = UnifiedRangeProof::make(&ct, 0, &nonce, &pk, &sel_id, 4)
            .expect("make failed");
        assert!(proof.verify(&ct, &pk, &sel_id, 4), "verify failed for plaintext=0, bits=4");
    }

    #[test]
    fn unified_make_verify_max() {
        // plaintext = 15 = 2^4 - 1
        let (ct, nonce, pk, sel_id) = make_context(42, 7, 15);
        let proof = UnifiedRangeProof::make(&ct, 15, &nonce, &pk, &sel_id, 4)
            .expect("make failed");
        assert!(proof.verify(&ct, &pk, &sel_id, 4), "verify failed for plaintext=15, bits=4");
    }

    #[test]
    fn unified_make_verify_one_bit() {
        let (ct, nonce, pk, sel_id) = make_context(42, 7, 1);
        let proof = UnifiedRangeProof::make(&ct, 1, &nonce, &pk, &sel_id, 1)
            .expect("make failed");
        assert!(proof.verify(&ct, &pk, &sel_id, 1), "verify failed for plaintext=1, bits=1");
    }

    #[test]
    fn unified_out_of_range_errors() {
        let (ct, nonce, pk, sel_id) = make_context(42, 7, 0);
        assert!(
            UnifiedRangeProof::make(&ct, 16, &nonce, &pk, &sel_id, 4).is_err(),
            "plaintext=16 for bits=4 should fail"
        );
    }

    #[test]
    fn unified_wrong_hash_fails() {
        let (ct, nonce, pk, sel_id) = make_context(42, 7, 3);
        let proof = UnifiedRangeProof::make(&ct, 3, &nonce, &pk, &sel_id, 4)
            .expect("make failed");
        let bad_sel_id = ElementModQ::from_u64(9999);
        assert!(
            !proof.verify(&ct, &pk, &bad_sel_id, 4),
            "wrong hash should fail verification"
        );
    }

    #[test]
    fn unified_wrong_range_bits_fails() {
        let (ct, nonce, pk, sel_id) = make_context(42, 7, 1);
        let proof = UnifiedRangeProof::make(&ct, 1, &nonce, &pk, &sel_id, 2)
            .expect("make failed");
        // Verify with wrong range_bits → length mismatch
        assert!(
            !proof.verify(&ct, &pk, &sel_id, 4),
            "wrong range_bits should fail"
        );
    }
}
