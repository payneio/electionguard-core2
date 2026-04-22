//! Disjunctive Chaum-Pedersen proof.
//!
//! Proves that a ciphertext encrypts either 0 or 1 without revealing which.
//!
//! Protocol (simulate the wrong branch, real-commit the correct one):
//!
//! Given `(α, β) = (g^r, g^m · K^r)` with m ∈ {0, 1}:
//! - Adjusted data for case j: `β_j = β · g^{-j} = K^r` when m == j.
//! - Real branch (j == m): commit `(a_j, b_j) = (g^u, K^u)`, derive its
//!   challenge from `c_j = c − c_{1-j} mod Q`, respond `v_j = u − c_j · r mod Q`.
//! - Simulated branch (j != m): choose random `c_s, v_s`, set
//!   `a_s = g^{v_s} · α^{c_s}` and `b_s = K^{v_s} · β_s^{c_s}`.
//!
//! Overall challenge: `c = H(sel_id; 0x24, K, α, β, a₀, b₀, a₁, b₁)`
//! Soundness: `c₀ + c₁ = c mod Q`.
//!
//! Verification equations (per sub-proof j):
//! - `g^{v_j} · α^{c_j} = a_j`
//! - `K^{v_j} · (β / g^j)^{c_j} = b_j`

use serde::{Deserialize, Serialize};

use crate::elgamal::ElGamalCiphertext;
use crate::error::Result;
use crate::group::{
    ElementModP, ElementModQ,
    add_mod_q, sub_mod_q,
    g_pow, pow_mod_p, mul_mod_p, div_mod_p,
};
use crate::hash::{hash_elems_v21, HashableValue};
use crate::nonces::Nonces;
use crate::proof::ChaumPedersenProof;

/// Domain separator for the disjunctive selection proof challenge hash.
const DS_DISJUNCTIVE: u8 = 0x24;

// ── DisjunctiveChaumPedersenProof ───────────────────────────────────────────

/// Proves a ciphertext encrypts 0 or 1 (disjunctive proof).
///
/// Contains two sub-proofs: one for the "encrypts 0" branch, one for
/// the "encrypts 1" branch. Exactly one is the real proof; the other is
/// a simulation. The prover knows which is which, but a verifier cannot tell.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisjunctiveChaumPedersenProof {
    /// Sub-proof asserting the ciphertext encrypts 0.
    pub proof_zero: ChaumPedersenProof,
    /// Sub-proof asserting the ciphertext encrypts 1.
    pub proof_one: ChaumPedersenProof,
    /// Overall challenge `c = H(...)`, equal to `c₀ + c₁ mod Q`.
    pub challenge: ElementModQ,
}

impl DisjunctiveChaumPedersenProof {
    /// Generate a proof that `ciphertext` encrypts `plaintext ∈ {0, 1}`.
    ///
    /// # Arguments
    /// * `ciphertext`       — `(α, β)` = `(g^nonce, g^plaintext · K^nonce)`.
    /// * `plaintext`        — Must be 0 or 1.
    /// * `nonce`            — The encryption nonce `r` used to create the ciphertext.
    /// * `public_key`       — Election public key `K`.
    /// * `seed`             — Randomness source for commitment nonces.
    /// * `selection_enc_id` — Per-ballot selection encryption identifier `H_I`.
    pub fn make(
        ciphertext: &ElGamalCiphertext,
        plaintext: u64,
        nonce: &ElementModQ,
        public_key: &ElementModP,
        seed: &ElementModQ,
        selection_enc_id: &ElementModQ,
    ) -> Result<Self> {
        if plaintext > 1 {
            return Err(crate::error::Error::InvalidProof(format!(
                "DisjunctiveChaumPedersenProof: plaintext must be 0 or 1, got {}",
                plaintext
            )));
        }

        // Derive commitment nonce and simulated values from seed.
        let nonces = Nonces::new(seed);
        let u = nonces.get(0)?;       // real commitment nonce w
        let c_sim = nonces.get(1)?;   // simulated challenge c_{1-plaintext}
        let v_sim = nonces.get(2)?;   // simulated response  v_{1-plaintext}

        let alpha = &ciphertext.pad;  // g^r
        let beta  = &ciphertext.data; // g^m · K^r

        // g^{-1} mod P (multiplicative inverse of g)
        let g1 = g_pow(ElementModQ::one()); // g^1
        let g_inv = div_mod_p(ElementModP::one(), &g1)?; // g^{-1}

        match plaintext {
            0 => {
                // Real proof for zero: β₀ = β / g^0 = β = K^r.
                let (a0, b0) = (g_pow(&u), pow_mod_p(public_key, &u));

                // Simulated proof for one: β₁ = β / g = β · g^{-1}.
                let beta_adj1 = mul_mod_p(beta, &g_inv);
                let a1 = mul_mod_p(&g_pow(&v_sim), &pow_mod_p(alpha, &c_sim));
                let b1 = mul_mod_p(&pow_mod_p(public_key, &v_sim), &pow_mod_p(&beta_adj1, &c_sim));

                // Overall challenge.
                let c = challenge_hash(
                    selection_enc_id, public_key, alpha, beta,
                    &a0, &b0, &a1, &b1,
                )?;

                // Real challenge for zero: c₀ = c − c_sim mod Q.
                let c0 = sub_mod_q(&c, &c_sim);
                // Real response: v₀ = u − c₀ · r mod Q.
                let v0 = sub_mod_q(&u, &crate::group::mul_mod_q(&c0, nonce));

                let proof_zero = ChaumPedersenProof { pad: a0, data: b0, challenge: c0, response: v0 };
                let proof_one  = ChaumPedersenProof { pad: a1, data: b1, challenge: c_sim, response: v_sim };

                Ok(Self { proof_zero, proof_one, challenge: c })
            }
            1 => {
                // Simulated proof for zero: β₀ = β = K^r (when m=1, β₀ ≠ K^r, so we simulate).
                let beta_adj0 = beta; // β / g^0 = β
                let a0 = mul_mod_p(&g_pow(&v_sim), &pow_mod_p(alpha, &c_sim));
                let b0 = mul_mod_p(&pow_mod_p(public_key, &v_sim), &pow_mod_p(beta_adj0, &c_sim));

                // Real proof for one: β₁ = β / g = β · g^{-1} = K^r.
                let (a1, b1) = (g_pow(&u), pow_mod_p(public_key, &u));

                // Overall challenge.
                let c = challenge_hash(
                    selection_enc_id, public_key, alpha, beta,
                    &a0, &b0, &a1, &b1,
                )?;

                // Real challenge for one: c₁ = c − c_sim mod Q.
                let c1 = sub_mod_q(&c, &c_sim);
                // Real response: v₁ = u − c₁ · r mod Q.
                let v1 = sub_mod_q(&u, &crate::group::mul_mod_q(&c1, nonce));

                let proof_zero = ChaumPedersenProof { pad: a0, data: b0, challenge: c_sim, response: v_sim };
                let proof_one  = ChaumPedersenProof { pad: a1, data: b1, challenge: c1,    response: v1 };

                Ok(Self { proof_zero, proof_one, challenge: c })
            }
            _ => unreachable!(),
        }
    }

    /// Verify the proof against the ciphertext and public key.
    ///
    /// Returns `true` iff all equations hold and the challenge is consistent.
    ///
    /// # Arguments
    /// * `ciphertext`    — The ciphertext `(α, β)` being proved.
    /// * `public_key`    — Election public key `K`.
    /// * `extended_hash` — The context hash (must match what was used in `make`).
    pub fn verify(
        &self,
        ciphertext: &ElGamalCiphertext,
        public_key: &ElementModP,
        extended_hash: &ElementModQ,
    ) -> bool {
        let alpha = &ciphertext.pad;
        let beta  = &ciphertext.data;

        let c0 = &self.proof_zero.challenge;
        let v0 = &self.proof_zero.response;
        let a0 = &self.proof_zero.pad;
        let b0 = &self.proof_zero.data;

        let c1 = &self.proof_one.challenge;
        let v1 = &self.proof_one.response;
        let a1 = &self.proof_one.pad;
        let b1 = &self.proof_one.data;

        // 1. Recompute overall challenge.
        let c = match challenge_hash(extended_hash, public_key, alpha, beta, a0, b0, a1, b1) {
            Ok(v) => v,
            Err(_) => return false,
        };

        // 2a. The stored top-level challenge must match the recomputed one.
        if c != self.challenge {
            return false;
        }

        // 2b. Check challenge sum: c₀ + c₁ = c mod Q.
        if add_mod_q(c0, c1) != c {
            return false;
        }

        // 3. Verify zero sub-proof: β_adj₀ = β / g^0 = β.
        if !verify_sub_proof(public_key, alpha, beta, v0, c0, a0, b0) {
            return false;
        }

        // 4. Verify one sub-proof: β_adj₁ = β / g^1.
        let g1 = g_pow(ElementModQ::one());
        let beta_adj1 = match div_mod_p(beta, &g1) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if !verify_sub_proof(public_key, alpha, &beta_adj1, v1, c1, a1, b1) {
            return false;
        }

        true
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Compute the overall challenge hash.
///
/// `c = H(key; 0x24, K, α, β, a₀, b₀, a₁, b₁)`
#[allow(clippy::too_many_arguments)]
fn challenge_hash(
    key: &ElementModQ,
    public_key: &ElementModP,
    alpha: &ElementModP,
    beta: &ElementModP,
    a0: &ElementModP,
    b0: &ElementModP,
    a1: &ElementModP,
    b1: &ElementModP,
) -> Result<ElementModQ> {
    hash_elems_v21(
        key,
        DS_DISJUNCTIVE,
        &[
            HashableValue::ModP(public_key),
            HashableValue::ModP(alpha),
            HashableValue::ModP(beta),
            HashableValue::ModP(a0),
            HashableValue::ModP(b0),
            HashableValue::ModP(a1),
            HashableValue::ModP(b1),
        ],
    )
}

/// Verify a single Chaum-Pedersen sub-proof.
///
/// Checks:
/// - `g^v · α^c = a`
/// - `K^v · adj^c = b`
fn verify_sub_proof(
    public_key: &ElementModP,
    alpha: &ElementModP,
    adj: &ElementModP,
    v: &ElementModQ,
    c: &ElementModQ,
    a: &ElementModP,
    b: &ElementModP,
) -> bool {
    // lhs_a = g^v · α^c
    let lhs_a = mul_mod_p(&g_pow(v), &pow_mod_p(alpha, c));
    // lhs_b = K^v · adj^c
    let lhs_b = mul_mod_p(&pow_mod_p(public_key, v), &pow_mod_p(adj, c));
    lhs_a == *a && lhs_b == *b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::elgamal_encrypt;

    fn make_context(secret: u64, nonce_val: u64, plaintext: u64)
        -> (ElGamalCiphertext, ElementModQ, ElementModP, ElementModQ, ElementModQ)
    {
        let secret_key = ElementModQ::from_u64(secret);
        let public_key = g_pow(&secret_key);
        let nonce = ElementModQ::from_u64(nonce_val);
        let ct = elgamal_encrypt(plaintext, &nonce, &public_key);
        let seed = ElementModQ::from_u64(123);
        let sel_id = ElementModQ::from_u64(456);
        (ct, nonce, public_key, seed, sel_id)
    }

    #[test]
    fn disjunctive_make_verify_zero() {
        let (ct, nonce, pk, seed, sel_id) = make_context(42, 7, 0);
        let proof = DisjunctiveChaumPedersenProof::make(&ct, 0, &nonce, &pk, &seed, &sel_id)
            .expect("make failed");
        assert!(proof.verify(&ct, &pk, &sel_id), "verify failed for plaintext=0");
    }

    #[test]
    fn disjunctive_make_verify_one() {
        let (ct, nonce, pk, seed, sel_id) = make_context(42, 7, 1);
        let proof = DisjunctiveChaumPedersenProof::make(&ct, 1, &nonce, &pk, &seed, &sel_id)
            .expect("make failed");
        assert!(proof.verify(&ct, &pk, &sel_id), "verify failed for plaintext=1");
    }

    #[test]
    fn disjunctive_wrong_key_fails() {
        let (ct, nonce, pk, seed, sel_id) = make_context(42, 7, 1);
        let proof = DisjunctiveChaumPedersenProof::make(&ct, 1, &nonce, &pk, &seed, &sel_id)
            .expect("make failed");
        let wrong_key = g_pow(&ElementModQ::from_u64(999));
        assert!(!proof.verify(&ct, &wrong_key, &sel_id), "should fail with wrong key");
    }

    #[test]
    fn disjunctive_invalid_plaintext_errors() {
        let (ct, nonce, pk, seed, sel_id) = make_context(42, 7, 0);
        assert!(
            DisjunctiveChaumPedersenProof::make(&ct, 2, &nonce, &pk, &seed, &sel_id).is_err(),
            "plaintext=2 should be an error"
        );
    }
}
