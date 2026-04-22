//! Ranged Chaum-Pedersen proof.
//!
//! Proves a ciphertext encrypts a value `v ∈ [0, range_limit]`.
//!
//! This is a compound proof of `range_limit + 1` sub-proofs, one for each
//! possible value. All sub-proof commitments contribute to a single overall
//! challenge, and the corresponding sub-challenges must sum to it.
//!
//! For each `j ∈ 0..=range_limit`:
//! - If `j == plaintext`: real Chaum-Pedersen proof (knows `r`).
//! - If `j != plaintext`: simulated proof (faked with random `c_j, v_j`).
//!
//! Verification:
//! - Recompute `c = H(ext_hash; 0x2D, K, α, β, a₀, b₀, ..., aₙ, bₙ)`.
//! - Check `Σ cⱼ = c mod Q`.
//! - For each `j`: `g^{vⱼ} · α^{cⱼ} = aⱼ` and `K^{vⱼ} · (β/g^j)^{cⱼ} = bⱼ`.

use serde::{Deserialize, Serialize};

use crate::elgamal::ElGamalCiphertext;
use crate::error::Result;
use crate::group::{
    ElementModP, ElementModQ,
    add_mod_q, sub_mod_q,
    g_pow, pow_mod_p, mul_mod_p, div_mod_p,
};
use crate::group::constants::EG_DS_RANGE_PROOF;
use crate::hash::{hash_elems_v21, HashableValue};
use crate::nonces::Nonces;
use crate::proof::ChaumPedersenProof;

// ── RangedChaumPedersenProof ─────────────────────────────────────────────────

/// Ranged Chaum-Pedersen proof: proves a ciphertext encrypts a value in `[0, limit]`.
///
/// Composed of `(limit + 1)` individual proofs, with a single shared challenge.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangedChaumPedersenProof {
    /// The inclusive upper bound of the range.
    pub range_limit: u64,
    /// One sub-proof per possible value `0..=range_limit`.
    pub individual_proofs: Vec<ChaumPedersenProof>,
    /// Overall challenge `c = H(...)` = sum of all sub-challenges.
    pub challenge: ElementModQ,
}

impl RangedChaumPedersenProof {
    /// Generate a ranged proof.
    ///
    /// # Arguments
    /// * `ciphertext`       — `(α, β) = (g^nonce, g^plaintext · K^nonce)`.
    /// * `plaintext`        — Must be `≤ range_limit`.
    /// * `nonce`            — Encryption nonce `r`.
    /// * `public_key`       — Election public key `K`.
    /// * `seed`             — Randomness source for commitments.
    /// * `range_limit`      — Inclusive upper bound `L`.
    /// * `selection_enc_id` — Per-ballot selection encryption identifier.
    pub fn make(
        ciphertext: &ElGamalCiphertext,
        plaintext: u64,
        nonce: &ElementModQ,
        public_key: &ElementModP,
        seed: &ElementModQ,
        range_limit: u64,
        selection_enc_id: &ElementModQ,
    ) -> Result<Self> {
        if plaintext > range_limit {
            return Err(crate::error::Error::InvalidProof(format!(
                "RangedChaumPedersenProof: plaintext {} > range_limit {}",
                plaintext, range_limit
            )));
        }

        let n = (range_limit + 1) as usize;
        let nonces = Nonces::new(seed);

        // u = commitment nonce for the real sub-proof (index = range_limit + 1).
        let u = nonces.get(range_limit + 1)?;

        let alpha = &ciphertext.pad;
        let beta  = &ciphertext.data;

        // Build per-j commitments and simulated challenges/responses.
        // We'll fill index `plaintext` later with the real values.
        let mut a_list: Vec<ElementModP> = Vec::with_capacity(n);
        let mut b_list: Vec<ElementModP> = Vec::with_capacity(n);
        let mut c_list: Vec<ElementModQ> = Vec::with_capacity(n);
        let mut v_list: Vec<ElementModQ> = Vec::with_capacity(n);

        // Precompute g^j for j in 0..=L.
        let g_pows: Vec<ElementModP> = (0u64..=range_limit)
            .map(|j| g_pow(&ElementModQ::from_u64(j)))
            .collect();

        for j in 0..=range_limit {
            if j == plaintext {
                // Real commitment: a_v = g^u, b_v = K^u.
                a_list.push(g_pow(&u));
                b_list.push(pow_mod_p(public_key, &u));
                // Placeholder challenges/responses (filled after overall challenge).
                c_list.push(ElementModQ::from_u64(0));
                v_list.push(ElementModQ::from_u64(0));
            } else {
                // Simulated: c_j = nonces[j], v_j = nonces[range_limit + 2 + j].
                let c_j = nonces.get(j)?;
                let v_j = nonces.get(range_limit + 2 + j)?;
                // adj_j = β / g^j
                let adj_j = div_mod_p(beta, &g_pows[j as usize])?;
                // a_j = g^{v_j} · α^{c_j}
                let a_j = mul_mod_p(&g_pow(&v_j), &pow_mod_p(alpha, &c_j));
                // b_j = K^{v_j} · adj_j^{c_j}
                let b_j = mul_mod_p(&pow_mod_p(public_key, &v_j), &pow_mod_p(&adj_j, &c_j));

                a_list.push(a_j);
                b_list.push(b_j);
                c_list.push(c_j);
                v_list.push(v_j);
            }
        }

        // Compute overall challenge.
        let c = ranged_challenge_hash(
            selection_enc_id, public_key, alpha, beta,
            &a_list, &b_list,
        )?;

        // Fill in the real sub-proof.
        {
            let idx = plaintext as usize;
            // c_real = c − Σ_{j≠real} c_j mod Q
            let mut c_sum = ElementModQ::from_u64(0);
            for (i, cj) in c_list.iter().enumerate() {
                if i != idx {
                    c_sum = add_mod_q(&c_sum, cj);
                }
            }
            let c_real = sub_mod_q(&c, &c_sum);
            let v_real = sub_mod_q(&u, &crate::group::mul_mod_q(&c_real, nonce));
            c_list[idx] = c_real;
            v_list[idx] = v_real;
        }

        // Build ChaumPedersenProof per j.
        let individual_proofs: Vec<ChaumPedersenProof> = (0..n)
            .map(|j| ChaumPedersenProof {
                pad:       a_list[j].clone(),
                data:      b_list[j].clone(),
                challenge: c_list[j].clone(),
                response:  v_list[j].clone(),
            })
            .collect();

        Ok(Self { range_limit, individual_proofs, challenge: c })
    }

    /// Verify the ranged proof.
    ///
    /// Returns `true` iff all verification equations hold.
    pub fn verify(
        &self,
        ciphertext: &ElGamalCiphertext,
        public_key: &ElementModP,
        extended_hash: &ElementModQ,
    ) -> bool {
        let alpha = &ciphertext.pad;
        let beta  = &ciphertext.data;
        let n = (self.range_limit + 1) as usize;

        if self.individual_proofs.len() != n {
            return false;
        }

        let a_list: Vec<&ElementModP> = self.individual_proofs.iter().map(|p| &p.pad).collect();
        let b_list: Vec<&ElementModP> = self.individual_proofs.iter().map(|p| &p.data).collect();

        // 1. Recompute overall challenge.
        let a_owned: Vec<ElementModP> = a_list.iter().map(|p| (*p).clone()).collect();
        let b_owned: Vec<ElementModP> = b_list.iter().map(|p| (*p).clone()).collect();
        let c = match ranged_challenge_hash(extended_hash, public_key, alpha, beta, &a_owned, &b_owned) {
            Ok(v) => v,
            Err(_) => return false,
        };

        // 2. Check challenge sum.
        let mut c_sum = ElementModQ::from_u64(0);
        for p in &self.individual_proofs {
            c_sum = add_mod_q(&c_sum, &p.challenge);
        }
        if c_sum != c {
            return false;
        }

        // 3. Verify each sub-proof.
        for (j, proof) in self.individual_proofs.iter().enumerate() {
            let g_j = g_pow(&ElementModQ::from_u64(j as u64));
            let adj_j = match div_mod_p(beta, &g_j) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let v = &proof.response;
            let c_j = &proof.challenge;
            let a = &proof.pad;
            let b = &proof.data;

            // g^v · α^c = a
            let lhs_a = mul_mod_p(&g_pow(v), &pow_mod_p(alpha, c_j));
            if lhs_a != *a {
                return false;
            }
            // K^v · adj^c = b
            let lhs_b = mul_mod_p(&pow_mod_p(public_key, v), &pow_mod_p(&adj_j, c_j));
            if lhs_b != *b {
                return false;
            }
        }

        true
    }
}

// ── Helper ───────────────────────────────────────────────────────────────────

/// Compute the overall ranged proof challenge.
///
/// `c = H(key; EG_DS_RANGE_PROOF, K, α, β, a₀, b₀, ..., aₙ, bₙ)`
fn ranged_challenge_hash(
    key: &ElementModQ,
    public_key: &ElementModP,
    alpha: &ElementModP,
    beta: &ElementModP,
    a_list: &[ElementModP],
    b_list: &[ElementModP],
) -> Result<ElementModQ> {
    let mut args: Vec<HashableValue<'_>> = Vec::with_capacity(3 + 2 * a_list.len());
    args.push(HashableValue::ModP(public_key));
    args.push(HashableValue::ModP(alpha));
    args.push(HashableValue::ModP(beta));
    for (a, b) in a_list.iter().zip(b_list.iter()) {
        args.push(HashableValue::ModP(a));
        args.push(HashableValue::ModP(b));
    }
    hash_elems_v21(key, EG_DS_RANGE_PROOF, &args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::elgamal_encrypt;

    fn make_context(secret: u64, nonce_val: u64, plaintext: u64)
        -> (ElGamalCiphertext, ElementModQ, ElementModP, ElementModQ, ElementModQ)
    {
        let sk = ElementModQ::from_u64(secret);
        let pk = g_pow(&sk);
        let nonce = ElementModQ::from_u64(nonce_val);
        let ct = elgamal_encrypt(plaintext, &nonce, &pk);
        let seed = ElementModQ::from_u64(777);
        let sel_id = ElementModQ::from_u64(888);
        (ct, nonce, pk, seed, sel_id)
    }

    #[test]
    fn ranged_make_verify_zero() {
        let (ct, nonce, pk, seed, sel_id) = make_context(42, 7, 0);
        let proof = RangedChaumPedersenProof::make(&ct, 0, &nonce, &pk, &seed, 3, &sel_id)
            .expect("make failed");
        assert!(proof.verify(&ct, &pk, &sel_id), "verify failed for plaintext=0, limit=3");
    }

    #[test]
    fn ranged_make_verify_middle() {
        let (ct, nonce, pk, seed, sel_id) = make_context(42, 7, 2);
        let proof = RangedChaumPedersenProof::make(&ct, 2, &nonce, &pk, &seed, 3, &sel_id)
            .expect("make failed");
        assert!(proof.verify(&ct, &pk, &sel_id), "verify failed for plaintext=2, limit=3");
    }

    #[test]
    fn ranged_make_verify_limit() {
        let (ct, nonce, pk, seed, sel_id) = make_context(42, 7, 3);
        let proof = RangedChaumPedersenProof::make(&ct, 3, &nonce, &pk, &seed, 3, &sel_id)
            .expect("make failed");
        assert!(proof.verify(&ct, &pk, &sel_id), "verify failed for plaintext=3, limit=3");
    }

    #[test]
    fn ranged_out_of_range_errors() {
        let (ct, nonce, pk, seed, sel_id) = make_context(42, 7, 0);
        assert!(
            RangedChaumPedersenProof::make(&ct, 4, &nonce, &pk, &seed, 3, &sel_id).is_err(),
            "plaintext > limit should be an error"
        );
    }
}
