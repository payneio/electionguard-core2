//! Constant Chaum-Pedersen proof.
//!
//! Proves that a ciphertext accumulation encrypts exactly `constant`.
//!
//! Given accumulated `(α, β) = (g^R, g^S · K^R)` where `R` is the accumulated nonce
//! sum and `S` is the sum of all plaintext values (= `constant`):
//!
//! We prove DLEQ: `α = g^R` and `β_adj = β / g^S = K^R`
//!
//! Sigma protocol:
//! - Commit: `u` random, `a = g^u`, `b = K^u`
//! - Challenge: `c = H(ext_hash; 0x23, K, α, β, a, b)`
//! - Response:  `v = u − c · R mod Q`
//!
//! Verification:
//! - `g^v · α^c = a`
//! - `K^v · (β / g^S)^c = b`

use serde::{Deserialize, Serialize};

use crate::elgamal::ElGamalCiphertext;
use crate::error::Result;
use crate::group::{
    ElementModP, ElementModQ,
    g_pow, pow_mod_p, mul_mod_p, div_mod_p,
};
use crate::hash::{hash_elems_v21, HashableValue};
use crate::nonces::Nonces;
use crate::proof::ChaumPedersenProof;

/// Domain separator for the constant proof challenge hash.
const DS_CONSTANT: u8 = 0x23;

// ── ConstantChaumPedersenProof ────────────────────────────────────────────────

/// Constant Chaum-Pedersen proof: proves a ciphertext accumulation
/// encrypts exactly `constant` (the contest vote limit).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstantChaumPedersenProof {
    /// The underlying Chaum-Pedersen proof.
    pub proof: ChaumPedersenProof,
    /// The claimed constant `S` (sum of all plaintext selections).
    pub constant: u64,
}

impl ConstantChaumPedersenProof {
    /// Generate a constant proof.
    ///
    /// # Arguments
    /// * `ciphertext`    — Accumulated `(α, β) = (g^R, g^S · K^R)`.
    /// * `constant`      — The claimed plaintext sum `S`.
    /// * `nonce`         — The accumulated encryption nonce `R = Σ rᵢ`.
    /// * `public_key`    — Election public key `K`.
    /// * `seed`          — Randomness source for commitment nonces.
    /// * `extended_hash` — Extended base hash `H_E` used in the challenge.
    pub fn make(
        ciphertext: &ElGamalCiphertext,
        constant: u64,
        nonce: &ElementModQ,
        public_key: &ElementModP,
        seed: &ElementModQ,
        extended_hash: &ElementModQ,
    ) -> Result<Self> {
        let nonces = Nonces::new(seed);
        let u = nonces.get(0)?; // commitment nonce w

        let alpha = &ciphertext.pad;
        let beta  = &ciphertext.data;

        // a = g^u, b = K^u
        let a = g_pow(&u);
        let b = pow_mod_p(public_key, &u);

        // Challenge c = H(ext_hash; 0x23, K, α, β, a, b)
        let c = hash_elems_v21(
            extended_hash,
            DS_CONSTANT,
            &[
                HashableValue::ModP(public_key),
                HashableValue::ModP(alpha),
                HashableValue::ModP(beta),
                HashableValue::ModP(&a),
                HashableValue::ModP(&b),
            ],
        )?;

        // Response v = u − c · R mod Q
        let v = crate::group::sub_mod_q(&u, &crate::group::mul_mod_q(&c, nonce));

        let proof = ChaumPedersenProof { pad: a, data: b, challenge: c, response: v };
        Ok(Self { proof, constant })
    }

    /// Verify the constant proof.
    ///
    /// Returns `true` iff all verification equations hold.
    ///
    /// # Arguments
    /// * `ciphertext`    — The accumulated ciphertext `(α, β)`.
    /// * `public_key`    — Election public key `K`.
    /// * `extended_hash` — The context hash used in `make`.
    pub fn verify(
        &self,
        ciphertext: &ElGamalCiphertext,
        public_key: &ElementModP,
        extended_hash: &ElementModQ,
    ) -> bool {
        let alpha = &ciphertext.pad;
        let beta  = &ciphertext.data;

        let a = &self.proof.pad;
        let b = &self.proof.data;
        let c = &self.proof.challenge;
        let v = &self.proof.response;

        // 1. Recompute challenge.
        let c_expected = match hash_elems_v21(
            extended_hash,
            DS_CONSTANT,
            &[
                HashableValue::ModP(public_key),
                HashableValue::ModP(alpha),
                HashableValue::ModP(beta),
                HashableValue::ModP(a),
                HashableValue::ModP(b),
            ],
        ) {
            Ok(h) => h,
            Err(_) => return false,
        };

        if *c != c_expected {
            return false;
        }

        // 2. Compute β_adj = β / g^S.
        let g_s = g_pow(&ElementModQ::from_u64(self.constant));
        let beta_adj = match div_mod_p(beta, &g_s) {
            Ok(v) => v,
            Err(_) => return false,
        };

        // 3. Check g^v · α^c = a.
        let lhs_a = mul_mod_p(&g_pow(v), &pow_mod_p(alpha, c));
        if lhs_a != *a {
            return false;
        }

        // 4. Check K^v · (β/g^S)^c = b.
        let lhs_b = mul_mod_p(&pow_mod_p(public_key, v), &pow_mod_p(&beta_adj, c));
        if lhs_b != *b {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::{elgamal_encrypt, elgamal_accumulate};
    use crate::group::add_mod_q;

    fn make_context(secret: u64, nonces: &[u64], plaintexts: &[u64])
        -> (ElGamalCiphertext, ElementModQ, ElementModP, ElementModQ, ElementModQ)
    {
        let secret_key = ElementModQ::from_u64(secret);
        let public_key = g_pow(&secret_key);

        let cts: Vec<_> = nonces.iter().zip(plaintexts.iter()).map(|(n, p)| {
            elgamal_encrypt(*p, &ElementModQ::from_u64(*n), &public_key)
        }).collect();

        let refs: Vec<&_> = cts.iter().collect();
        let acc = elgamal_accumulate(&refs);

        // accumulated nonce = sum of nonces
        let mut nonce_sum = ElementModQ::from_u64(0);
        for &n in nonces {
            nonce_sum = add_mod_q(&nonce_sum, &ElementModQ::from_u64(n));
        }

        let seed = ElementModQ::from_u64(999);
        let ext_hash = ElementModQ::from_u64(111);

        (acc, nonce_sum, public_key, seed, ext_hash)
    }

    #[test]
    fn constant_make_verify() {
        // Two selections: 1 + 0 = 1
        let (acc, nonce, pk, seed, ext_hash) = make_context(42, &[7, 11], &[1, 0]);
        let constant = 1u64;
        let proof = ConstantChaumPedersenProof::make(&acc, constant, &nonce, &pk, &seed, &ext_hash)
            .expect("make failed");
        assert!(proof.verify(&acc, &pk, &ext_hash), "verify failed for correct constant");
    }

    #[test]
    fn constant_wrong_constant_fails() {
        let (acc, nonce, pk, seed, ext_hash) = make_context(42, &[7, 11], &[1, 0]);
        let proof = ConstantChaumPedersenProof::make(&acc, 1, &nonce, &pk, &seed, &ext_hash)
            .expect("make failed");
        // Create a fake proof claiming constant=2 (wrong)
        let mut bad = proof.clone();
        bad.constant = 2;
        assert!(!bad.verify(&acc, &pk, &ext_hash), "should fail with wrong constant");
    }
}
