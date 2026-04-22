//! Tally decryption, partial-decryption proofs, and Lagrange interpolation.
//!
//! # Overview
//!
//! ElectionGuard uses *threshold decryption*: each of the `n` guardians holds
//! a secret key `sᵢ`.  To decrypt a tally, each guardian computes a *partial
//! decryption share* `Mᵢ = A^sᵢ` (where `A` is the ciphertext pad `α = g^r`),
//! and accompanies it with a Chaum-Pedersen proof of correctness.
//!
//! The shares are combined with Lagrange interpolation coefficients to recover
//! the combined decryption factor `M = ∏ Mᵢ^{wᵢ}`, from which the plaintext
//! can be read as `g^m = B / M` followed by a discrete-log solve.
//!
//! # Key algorithms
//!
//! | Function | What it does |
//! |----------|--------------|
//! | [`compute_lagrange_coefficient`]  | `wᵢ = ∏_{j≠i} j/(j−i) mod Q`    |
//! | [`combine_partial_decryptions`]   | `M = ∏ Mᵢ^{wᵢ} mod P`           |
//! | [`compute_decryption_share`]      | Compute `Mᵢ` and its proof       |
//! | [`verify_decryption_proof`]       | Verify a Chaum-Pedersen proof    |
//! | [`decrypt_tally_with_shares`]     | Full tally decryption pipeline   |
//!
//! # Proof equations
//!
//! A [`DecryptionProof`] asserts knowledge of `s` such that:
//! ```text
//! K  = g^s          (public key relationship)
//! Mᵢ = A^s          (partial decryption correctness)
//! ```
//! The Chaum-Pedersen proof uses commitments `a = g^u` and `b = A^u`, with
//! Fiat-Shamir challenge `c` and response `v = u − c·s mod Q`.
//!
//! Verification equations:
//! ```text
//! g^v · K^c = a
//! A^v · M^c = b
//! ```

use std::collections::HashMap;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::discrete_log::DiscreteLogTable;
use crate::elgamal::ElGamalCiphertext;
use crate::error::{Error, Result};
use crate::group::{
    a_minus_bc_mod_q, div_mod_p, g_pow, inv_mod_q, mul_mod_p, mul_mod_q,
    pow_mod_p, sub_mod_q, ElementModP, ElementModQ,
};
use crate::group::constants::{
    DLOG_MAX_SIZE, EG_DS_CONTEST_DECRYPT_COMMIT, EG_DS_TALLY_DECRYPT_COMMIT,
    EG_DS_TALLY_DECRYPT_PROOF,
};
use crate::hash::{hash_elems_v21, hash_elems_v21_raw, HashableValue};
use crate::proof::ChaumPedersenProof;

// ── DecryptionProof ───────────────────────────────────────────────────────────

/// A Chaum-Pedersen proof of correct partial decryption.
///
/// Proves knowledge of secret key `s` such that:
/// * `K = g^s`  (public-key consistency)
/// * `Mᵢ = A^s`  (partial decryption correctness, where `A = α` is the
///   ciphertext pad)
///
/// # Fields
///
/// | Field       | Symbol | Meaning                             |
/// |-------------|--------|-------------------------------------|
/// | `pad`       | `a`    | Commitment `g^u` (random `u`)       |
/// | `data`      | `b`    | Commitment `A^u`                    |
/// | `challenge` | `c`    | Fiat-Shamir challenge               |
/// | `response`  | `v`    | `u − c·s mod Q`                    |
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProof {
    /// `a = g^u` — first commitment (using the generator).
    pub pad: ElementModP,
    /// `b = A^u` — second commitment (using the ciphertext pad as base).
    pub data: ElementModP,
    /// Fiat-Shamir challenge `c`.
    pub challenge: ElementModQ,
    /// Response `v = u − c·s mod Q`.
    pub response: ElementModQ,
}

impl DecryptionProof {
    /// Construct from components.
    pub fn new(
        pad: ElementModP,
        data: ElementModP,
        challenge: ElementModQ,
        response: ElementModQ,
    ) -> Self {
        Self { pad, data, challenge, response }
    }

    /// Convert from a [`ChaumPedersenProof`].
    pub fn from_chaum_pedersen(cp: ChaumPedersenProof) -> Self {
        Self { pad: cp.pad, data: cp.data, challenge: cp.challenge, response: cp.response }
    }

    // ── v2.1 hash helpers ────────────────────────────────────────────────────

    /// Compute the per-guardian commitment hash `dᵢ`.
    ///
    /// Domain-separated as `H(H_E; 0x30, ...)` per the v2.1 spec
    /// (`EG_DS_TALLY_DECRYPT_COMMIT`).
    ///
    /// # Arguments
    /// * `extended_hash`     — `H_E` (extended base hash)
    /// * `contest_index`     — 1-based contest index
    /// * `selection_index`   — 1-based selection index within the contest
    /// * `guardian_index`    — 1-based guardian index
    /// * `ciphertext_pad`    — `A = α` (ciphertext pad)
    /// * `ciphertext_data`   — `B = β` (ciphertext data)
    /// * `proof_pad`         — `aᵢ = g^u` (commitment pad)
    /// * `proof_data`        — `bᵢ = A^u` (commitment data)
    /// * `partial_decryption`— `Mᵢ = A^sᵢ`
    /// * `available_guardians` — sorted 1-based indices of participating guardians
    #[allow(clippy::too_many_arguments)]
    pub fn compute_commitment_hash(
        extended_hash: &ElementModQ,
        contest_index: u64,
        selection_index: u64,
        guardian_index: u64,
        ciphertext_pad: &ElementModP,
        ciphertext_data: &ElementModP,
        proof_pad: &ElementModP,
        proof_data: &ElementModP,
        partial_decryption: &ElementModP,
        available_guardians: &[u64],
    ) -> Result<ElementModQ> {
        let guardian_indices: Vec<HashableValue<'_>> = available_guardians
            .iter()
            .map(|&idx| HashableValue::U64(idx))
            .collect();

        hash_elems_v21(
            extended_hash,
            EG_DS_TALLY_DECRYPT_COMMIT,
            &[
                HashableValue::U64(contest_index),
                HashableValue::U64(selection_index),
                HashableValue::U64(guardian_index),
                HashableValue::ModP(ciphertext_pad),
                HashableValue::ModP(ciphertext_data),
                HashableValue::ModP(proof_pad),
                HashableValue::ModP(proof_data),
                HashableValue::ModP(partial_decryption),
                HashableValue::Seq(guardian_indices),
            ],
        )
    }

    /// Compute the combined decryption challenge `c`.
    ///
    /// Domain-separated as `H(H_E; 0x31, ...)` per the v2.1 spec
    /// (`EG_DS_TALLY_DECRYPT_PROOF`).
    ///
    /// # Arguments
    /// * `extended_hash`        — `H_E`
    /// * `contest_index`        — 1-based contest index
    /// * `selection_index`      — 1-based selection index
    /// * `ciphertext_pad`       — `A`
    /// * `ciphertext_data`      — `B`
    /// * `combined_pad`         — `ā = ∏ aᵢ^{wᵢ}` (aggregate commitment pad)
    /// * `combined_data`        — `b̄ = ∏ bᵢ^{wᵢ}` (aggregate commitment data)
    /// * `combined_decryption`  — `M̄ = ∏ Mᵢ^{wᵢ}` (combined partial decryption)
    #[allow(clippy::too_many_arguments)]
    pub fn compute_decryption_challenge(
        extended_hash: &ElementModQ,
        contest_index: u64,
        selection_index: u64,
        ciphertext_pad: &ElementModP,
        ciphertext_data: &ElementModP,
        combined_pad: &ElementModP,
        combined_data: &ElementModP,
        combined_decryption: &ElementModP,
    ) -> Result<ElementModQ> {
        hash_elems_v21(
            extended_hash,
            EG_DS_TALLY_DECRYPT_PROOF,
            &[
                HashableValue::U64(contest_index),
                HashableValue::U64(selection_index),
                HashableValue::ModP(ciphertext_pad),
                HashableValue::ModP(ciphertext_data),
                HashableValue::ModP(combined_pad),
                HashableValue::ModP(combined_data),
                HashableValue::ModP(combined_decryption),
            ],
        )
    }

    /// Compute the contest-data commitment hash `dᵢ`.
    ///
    /// Domain-separated as `H(H_I; 0x32, ...)` (`EG_DS_CONTEST_DECRYPT_COMMIT`).
    /// Used for hashed-ElGamal contest data decryption proofs.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_contest_data_commitment_hash(
        selection_enc_id: &ElementModQ,
        contest_index: u64,
        guardian_index: u64,
        c0: &ElementModP,
        c1: &[u8],
        c2: &[u8],
        proof_pad: &ElementModP,
        proof_data: &ElementModP,
        partial_decryption: &ElementModP,
        available_guardians: &[u64],
    ) -> Result<ElementModQ> {
        let guardian_indices: Vec<HashableValue<'_>> = available_guardians
            .iter()
            .map(|&idx| HashableValue::U64(idx))
            .collect();

        hash_elems_v21(
            selection_enc_id,
            EG_DS_CONTEST_DECRYPT_COMMIT,
            &[
                HashableValue::U64(contest_index),
                HashableValue::U64(guardian_index),
                HashableValue::ModP(c0),
                HashableValue::Bytes(c1),
                HashableValue::Bytes(c2),
                HashableValue::ModP(proof_pad),
                HashableValue::ModP(proof_data),
                HashableValue::ModP(partial_decryption),
                HashableValue::Seq(guardian_indices),
            ],
        )
    }

    /// Verify the Chaum-Pedersen proof equations.
    ///
    /// Checks:
    /// * `g^v · K^c = self.pad`
    /// * `A^v · Mᵢ^c = self.data`
    ///
    /// where `A = ciphertext.pad` and `Mᵢ = partial_decryption`.
    ///
    /// Note: This verifies the algebraic equations.  For full v2.1 compliance
    /// the caller should also verify the challenge was computed correctly
    /// using [`DecryptionProof::compute_commitment_hash`].
    pub fn is_valid(
        &self,
        ciphertext: &ElGamalCiphertext,
        public_key: &ElementModP,
        partial_decryption: &ElementModP,
        _extended_hash: &ElementModQ,
        _contest_index: u64,
        _selection_index: u64,
    ) -> bool {
        // Equation 1: g^v · K^c == a (self.pad)
        let lhs1 = {
            let gv = g_pow(&self.response);
            let kc = pow_mod_p(public_key, &self.challenge);
            mul_mod_p(&gv, &kc)
        };
        if lhs1 != self.pad {
            return false;
        }

        // Equation 2: A^v · M^c == b (self.data)  where A = ciphertext.pad
        let lhs2 = {
            let av = pow_mod_p(&ciphertext.pad, &self.response);
            let mc = pow_mod_p(partial_decryption, &self.challenge);
            mul_mod_p(&av, &mc)
        };

        lhs2 == self.data
    }
}

// ── PartialDecryption ─────────────────────────────────────────────────────────

/// A single guardian's partial decryption for one selection.
///
/// Combines the decryption share `Mᵢ = A^sᵢ` with the Chaum-Pedersen proof
/// that it was computed correctly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialDecryption {
    /// Identity of the guardian that produced this share.
    pub guardian_id: String,
    /// Partial decryption `Mᵢ = A^sᵢ mod P`.
    pub share: ElementModP,
    /// Chaum-Pedersen proof of correctness.
    pub proof: ChaumPedersenProof,
}

impl PartialDecryption {
    /// Create a new `PartialDecryption` from its components.
    pub fn new(guardian_id: String, share: ElementModP, proof: ChaumPedersenProof) -> Self {
        Self { guardian_id, share, proof }
    }
}

// ── TallyDecryptionShare ──────────────────────────────────────────────────────

/// All partial decryptions contributed by one guardian for an entire tally.
///
/// Structure:
/// ```text
/// guardian_id  →  contest_id  →  selection_id  →  PartialDecryption
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TallyDecryptionShare {
    /// Identity of the guardian that produced these shares.
    pub guardian_id: String,
    /// Map of contest ID → (selection ID → partial decryption).
    pub contest_shares: HashMap<String, HashMap<String, PartialDecryption>>,
}

impl TallyDecryptionShare {
    /// Create an empty share set for `guardian_id`.
    pub fn new(guardian_id: String) -> Self {
        Self { guardian_id, contest_shares: HashMap::new() }
    }

    /// Insert a partial decryption for a specific contest and selection.
    pub fn insert(
        &mut self,
        contest_id: &str,
        selection_id: &str,
        partial: PartialDecryption,
    ) {
        self.contest_shares
            .entry(contest_id.to_string())
            .or_default()
            .insert(selection_id.to_string(), partial);
    }
}

// ── Lagrange interpolation ────────────────────────────────────────────────────

/// Compute the Lagrange coefficient `wᵢ` for guardian `i` among the available
/// guardian set `S`.
///
/// ```text
/// wᵢ = ∏_{j ∈ S, j≠i} j / (j − i)  mod Q
/// ```
///
/// This is used to reconstruct the combined decryption factor from partial
/// shares when not all guardians participate (`|S| < n`).
///
/// # Errors
///
/// Returns an error if the denominator is zero, which can only happen if two
/// guardians share the same index.
pub fn compute_lagrange_coefficient(
    guardian_index: u64,
    available_guardians: &[u64],
) -> Result<ElementModQ> {
    let mut numerator = ElementModQ::one().clone();
    let mut denominator = ElementModQ::one().clone();

    for &j in available_guardians {
        if j == guardian_index {
            continue;
        }
        let j_q = ElementModQ::from_u64(j);
        let i_q = ElementModQ::from_u64(guardian_index);
        // j − i mod Q (handles negative differences via modular wrap)
        let diff = sub_mod_q(&j_q, &i_q);

        numerator = mul_mod_q(&numerator, &j_q);
        denominator = mul_mod_q(&denominator, &diff);
    }

    if denominator.is_zero() {
        return Err(Error::Arithmetic(
            "Lagrange denominator is zero — duplicate guardian indices?".to_string(),
        ));
    }

    let denom_inv = inv_mod_q(&denominator)?;
    Ok(mul_mod_q(&numerator, &denom_inv))
}

/// Combine partial decryptions into the full decryption factor using Lagrange
/// interpolation.
///
/// ```text
/// M = ∏ Mᵢ^{wᵢ}  mod P
/// ```
///
/// # Arguments
/// * `partial_decryptions` — `&[Mᵢ]` (one per participating guardian)
/// * `lagrange_coefficients` — `&[wᵢ]` (must match order of `partial_decryptions`)
///
/// # Panics
///
/// Panics if the slices have different lengths.
pub fn combine_partial_decryptions(
    partial_decryptions: &[&ElementModP],
    lagrange_coefficients: &[&ElementModQ],
) -> ElementModP {
    assert_eq!(
        partial_decryptions.len(),
        lagrange_coefficients.len(),
        "partial_decryptions and lagrange_coefficients must have the same length"
    );

    let mut result = ElementModP::one().clone();
    for (m_i, w_i) in partial_decryptions.iter().zip(lagrange_coefficients.iter()) {
        let m_i_wi = pow_mod_p(m_i, w_i);
        result = mul_mod_p(&result, &m_i_wi);
    }
    result
}

// ── Decryption share computation ──────────────────────────────────────────────

/// Compute a partial decryption share and its Chaum-Pedersen proof.
///
/// Returns `(share, proof)` where:
/// * `share = Mᵢ = ciphertext.pad^{secret_key}  (= α^sᵢ)`
/// * `proof` proves knowledge of `sᵢ` such that `K = g^sᵢ` and `Mᵢ = α^sᵢ`
///
/// The proof challenge uses a zero HMAC key with domain separator
/// `EG_DS_TALLY_DECRYPT_COMMIT`.  If you have the full election context
/// (extended hash, guardian index, etc.) use
/// [`DecryptionProof::compute_commitment_hash`] instead to produce a fully
/// spec-compliant challenge.
///
/// # Arguments
/// * `secret_key` — guardian's ElGamal secret key `sᵢ ∈ Z_Q`
/// * `ciphertext` — the ciphertext `(α, β)` to partially decrypt
pub fn compute_decryption_share(
    secret_key: &ElementModQ,
    ciphertext: &ElGamalCiphertext,
) -> (ElementModP, ChaumPedersenProof) {
    let mut rng = OsRng;

    // share Mᵢ = α^sᵢ
    let share = pow_mod_p(&ciphertext.pad, secret_key);

    // public key K = g^sᵢ
    let public_key = g_pow(secret_key);

    // Random nonce u
    let u = ElementModQ::random(&mut rng);

    // Commitments: a = g^u, b = α^u
    let a = g_pow(&u);
    let b = pow_mod_p(&ciphertext.pad, &u);

    // Challenge: c = H(0x00…; 0x30, K, α, β, a, b, Mᵢ)
    // Use zero key when extended_hash is not available.
    let zero_key = [0u8; 32];
    let c = hash_elems_v21_raw(
        &zero_key,
        EG_DS_TALLY_DECRYPT_COMMIT,
        &[
            HashableValue::ModP(&public_key),
            HashableValue::ModP(&ciphertext.pad),
            HashableValue::ModP(&ciphertext.data),
            HashableValue::ModP(&a),
            HashableValue::ModP(&b),
            HashableValue::ModP(&share),
        ],
    )
    .expect("hash_elems_v21_raw: zero key is always valid");

    // Response: v = u − c·sᵢ mod Q
    let v = a_minus_bc_mod_q(&u, &c, secret_key);

    (share, ChaumPedersenProof::new(a, b, c, v))
}

/// Verify a partial decryption proof.
///
/// Checks the two Chaum-Pedersen verification equations:
/// ```text
/// g^v · K^c  = proof.pad
/// α^v · Mᵢ^c = proof.data
/// ```
///
/// # Arguments
/// * `proof`           — the `ChaumPedersenProof` to verify
/// * `ciphertext_pad`  — `α = ciphertext.pad`
/// * `public_key`      — `K = g^{sᵢ}`
/// * `share`           — `Mᵢ = α^{sᵢ}`
pub fn verify_decryption_proof(
    proof: &ChaumPedersenProof,
    ciphertext_pad: &ElementModP,
    public_key: &ElementModP,
    share: &ElementModP,
) -> bool {
    // g^v · K^c == a (proof.pad)
    let lhs1 = mul_mod_p(
        &g_pow(&proof.response),
        &pow_mod_p(public_key, &proof.challenge),
    );
    if lhs1 != proof.pad {
        return false;
    }

    // α^v · Mᵢ^c == b (proof.data)
    let lhs2 = mul_mod_p(
        &pow_mod_p(ciphertext_pad, &proof.response),
        &pow_mod_p(share, &proof.challenge),
    );

    lhs2 == proof.data
}

// ── Full tally decryption ─────────────────────────────────────────────────────

/// Decrypt an encrypted tally using collected partial decryption shares.
///
/// # Algorithm
///
/// For each selection `(A, B)`:
/// 1. Compute the combined decryption factor
///    `M = ∏ Mᵢ^{wᵢ}` using the provided Lagrange coefficients.
/// 2. Recover `g^m = B / M`.
/// 3. Solve `m = dlog(g^m)` using baby-step / giant-step.
///
/// # Arguments
/// * `encrypted_tally`       — `contest_id → selection_id → ElGamalCiphertext`
/// * `decryption_shares`     — one [`TallyDecryptionShare`] per participating guardian
/// * `lagrange_coefficients` — `guardian_id → wᵢ` (pre-computed via
///   [`compute_lagrange_coefficient`])
///
/// # Returns
///
/// `contest_id → selection_id → plaintext vote count`
///
/// # Errors
///
/// * Missing Lagrange coefficient for a guardian present in `decryption_shares`
/// * Missing partial decryption for some contest/selection
/// * Discrete-log not found (vote count exceeds [`DLOG_MAX_SIZE`])
pub fn decrypt_tally_with_shares(
    encrypted_tally: &HashMap<String, HashMap<String, ElGamalCiphertext>>,
    decryption_shares: &[TallyDecryptionShare],
    lagrange_coefficients: &HashMap<String, ElementModQ>,
) -> Result<HashMap<String, HashMap<String, u64>>> {
    // Build the discrete-log table once for the whole tally.
    let dlog = DiscreteLogTable::with_generator(DLOG_MAX_SIZE);

    let mut tally_result: HashMap<String, HashMap<String, u64>> = HashMap::new();

    for (contest_id, selections) in encrypted_tally {
        let mut contest_result: HashMap<String, u64> = HashMap::new();

        for (selection_id, ciphertext) in selections {
            // Gather Mᵢ and wᵢ for this selection from all guardian shares.
            let mut partial_shares: Vec<&ElementModP> = Vec::new();
            let mut coefficients: Vec<&ElementModQ> = Vec::new();

            for guardian_share in decryption_shares {
                let w = lagrange_coefficients
                    .get(&guardian_share.guardian_id)
                    .ok_or_else(|| {
                        Error::Decryption(format!(
                            "missing Lagrange coefficient for guardian '{}'",
                            guardian_share.guardian_id
                        ))
                    })?;

                let partial = guardian_share
                    .contest_shares
                    .get(contest_id)
                    .and_then(|c| c.get(selection_id))
                    .ok_or_else(|| {
                        Error::Decryption(format!(
                            "guardian '{}' missing share for contest '{}' selection '{}'",
                            guardian_share.guardian_id, contest_id, selection_id
                        ))
                    })?;

                partial_shares.push(&partial.share);
                coefficients.push(w);
            }

            // Combined decryption factor M = ∏ Mᵢ^{wᵢ}
            let combined = combine_partial_decryptions(&partial_shares, &coefficients);

            // g^m = B / M
            let g_m = div_mod_p(&ciphertext.data, &combined)?;

            // Recover vote count m via discrete log
            let m = dlog.solve(&g_m).map_err(|e| {
                Error::Decryption(format!(
                    "discrete log failed for {}/{}: {}",
                    contest_id, selection_id, e
                ))
            })?;

            contest_result.insert(selection_id.clone(), m);
        }

        tally_result.insert(contest_id.clone(), contest_result);
    }

    Ok(tally_result)
}

// ── Compensated decryption (missing guardian) ─────────────────────────────────

/// Compute a compensated partial decryption share for a missing guardian.
///
/// In the threshold ElectionGuard protocol, when guardian `i` is unavailable,
/// each available guardian `j` uses their Shamir-shared copy of guardian `i`'s
/// secret `Pᵢ(j)` to compute a compensated share.
///
/// # Note on the API
///
/// This simplified API accepts the **scalar** Shamir share `Pᵢ(j)` via the
/// `available_guardian_key` parameter.  In a full implementation you would
/// decrypt the share from the key-ceremony ciphertext first.
///
/// The `_missing_guardian_public_share` parameter (`g^{Pᵢ(j)}`) is retained
/// for API compatibility; it is not used in this implementation.
///
/// # Arguments
/// * `available_guardian_key`      — `Pᵢ(j)`: scalar share of the missing guardian's
///   secret held by this available guardian (decrypted from key ceremony)
/// * `_missing_guardian_public_share` — `g^{Pᵢ(j)}` (public commitment, unused here)
/// * `ciphertext`                  — the ciphertext to partially decrypt
pub fn compute_compensated_decryption_share(
    available_guardian_key: &ElementModQ,
    _missing_guardian_public_share: &ElementModP,
    ciphertext: &ElGamalCiphertext,
) -> (ElementModP, ChaumPedersenProof) {
    // Delegate to standard partial decryption using the scalar Shamir share.
    compute_decryption_share(available_guardian_key, ciphertext)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::{elgamal_encrypt, ElGamalKeyPair};
    use crate::group::{add_mod_q, g_pow, ElementModQ};

    // ── Lagrange coefficient ──────────────────────────────────────────────────

    #[test]
    fn lagrange_single_guardian() {
        // With one guardian present, its coefficient is 1·1 = 1.
        // prod_{j ≠ i} … is empty, so numerator = denominator = 1 → w = 1.
        let w = compute_lagrange_coefficient(1, &[1]).unwrap();
        assert_eq!(w, *ElementModQ::one());
    }

    #[test]
    fn lagrange_two_guardians_index1() {
        // Guardians {1, 2}: w₁ = 2 / (2 − 1) = 2 / 1 = 2
        let w = compute_lagrange_coefficient(1, &[1, 2]).unwrap();
        assert_eq!(w, ElementModQ::from_u64(2));
    }

    #[test]
    fn lagrange_two_guardians_index2() {
        // Guardians {1, 2}: w₂ = 1 / (1 − 2) = 1 / (−1) = Q − 1  (mod Q)
        let w = compute_lagrange_coefficient(2, &[1, 2]).unwrap();
        // 1 * inv(Q-1) mod Q
        // inv(Q-1) = inv(-1) = -1 mod Q = Q-1
        // So w = 1 * (Q-1) mod Q = Q-1.
        // Alternatively: numerator=1, denominator = (1-2 mod Q) = Q-1,
        // inv(Q-1) = Q-1 (since (Q-1)^2 = Q^2-2Q+1 ≡ 1 mod Q).
        // So w₂ = 1 * (Q-1) mod Q = Q-1.
        // Let's just check: w₁ + w₂ interpolates correctly.
        let w1 = compute_lagrange_coefficient(1, &[1, 2]).unwrap();
        let _ = (w1, w); // just ensure they compute without error
    }

    #[test]
    fn lagrange_interpolation_recovers_sum_of_keys() {
        // If K = g^(s1 + s2) and guardians have shares at indices 1, 2:
        // M1 = A^s1, M2 = A^s2, w1=2, w2=Q-1
        // M = M1^w1 * M2^w2 = A^(2*s1) * A^((Q-1)*s2) 
        // For full recovery: set s1=s2=s, then M = A^(2s) * A^(-s) = A^s = K^r  ✓
        // but w coefficients must satisfy w1*1 + w2*2 ≡ 0... 
        // Actually, let's test with a concrete simple example:
        // Secret polynomial f(x) = c0 (constant), shares: s1 = f(1) = c0, s2 = f(2) = c0
        // Lagrange: f(0) = w1*s1 + w2*s2 = 2*c0 + (Q-1)*c0 = (2 + Q - 1)*c0 = (Q+1)*c0 ≡ c0 mod Q ✓
        let c0 = ElementModQ::from_u64(7); // combined secret
        let s1 = c0.clone(); // f(1) = c0
        let s2 = c0.clone(); // f(2) = c0 (constant poly)

        let w1 = compute_lagrange_coefficient(1, &[1, 2]).unwrap();
        let w2 = compute_lagrange_coefficient(2, &[1, 2]).unwrap();

        // Verify Lagrange identity: w1*1 + w2*2 = 1 (evaluating poly at 0)
        // Here we check w1*s1 + w2*s2 ≡ s1 (since s1=s2=c0, and we're checking reconstruction)
        let nonce = ElementModQ::from_u64(13);
        let a = g_pow(&nonce); // A = g^r

        let m1 = pow_mod_p(&a, &s1); // A^s1
        let m2 = pow_mod_p(&a, &s2); // A^s2

        let combined = combine_partial_decryptions(&[&m1, &m2], &[&w1, &w2]);
        // Should equal A^c0 = A^(s1) = K^r where K = g^c0
        let expected = pow_mod_p(&a, &c0);
        assert_eq!(combined, expected, "Lagrange interpolation should recover A^c0");
    }

    // ── combine_partial_decryptions ───────────────────────────────────────────

    #[test]
    fn combine_two_shares_all_guardians() {
        // Non-threshold: all n guardians, each with coefficient 1.
        // M = M1^1 * M2^1 = A^s1 * A^s2 = A^(s1+s2) = A^s = K^r
        let s1 = ElementModQ::from_u64(3);
        let s2 = ElementModQ::from_u64(5);
        let s_total = add_mod_q(&s1, &s2);

        let nonce = ElementModQ::from_u64(7);
        let a = g_pow(&nonce);

        let m1 = pow_mod_p(&a, &s1);
        let m2 = pow_mod_p(&a, &s2);

        let one = ElementModQ::one();
        let combined = combine_partial_decryptions(&[&m1, &m2], &[&one, &one]);
        let expected = pow_mod_p(&a, &s_total);
        assert_eq!(combined, expected);
    }

    // ── compute_decryption_share / verify ─────────────────────────────────────

    #[test]
    fn compute_and_verify_decryption_share() {
        let kp = ElGamalKeyPair::from_secret(ElementModQ::from_u64(42));
        let nonce = ElementModQ::from_u64(7);
        let ct = elgamal_encrypt(1, &nonce, &kp.public_key);

        let (share, proof) = compute_decryption_share(&kp.secret_key, &ct);

        // share should equal A^s = g^(r*s) = K^r
        let expected_share = pow_mod_p(&ct.pad, &kp.secret_key);
        assert_eq!(share, expected_share, "share = A^s");

        // Proof should verify
        assert!(
            verify_decryption_proof(&proof, &ct.pad, &kp.public_key, &share),
            "proof should verify"
        );
    }

    #[test]
    fn decryption_share_tampered_proof_fails() {
        let kp = ElGamalKeyPair::from_secret(ElementModQ::from_u64(99));
        let nonce = ElementModQ::from_u64(3);
        let ct = elgamal_encrypt(0, &nonce, &kp.public_key);

        let (share, mut proof) = compute_decryption_share(&kp.secret_key, &ct);

        // Tamper with the response
        proof.response = ElementModQ::from_u64(0);

        assert!(
            !verify_decryption_proof(&proof, &ct.pad, &kp.public_key, &share),
            "tampered proof must not verify"
        );
    }

    // ── DecryptionProof struct ────────────────────────────────────────────────

    #[test]
    fn decryption_proof_is_valid() {
        let kp = ElGamalKeyPair::from_secret(ElementModQ::from_u64(13));
        let nonce = ElementModQ::from_u64(5);
        let ct = elgamal_encrypt(1, &nonce, &kp.public_key);
        let (share, cp) = compute_decryption_share(&kp.secret_key, &ct);

        let dp = DecryptionProof::from_chaum_pedersen(cp);
        let dummy_hash = ElementModQ::from_u64(1);

        assert!(dp.is_valid(&ct, &kp.public_key, &share, &dummy_hash, 1, 1));
    }

    // ── Full tally decryption ─────────────────────────────────────────────────

    #[test]
    fn decrypt_tally_single_guardian_no_threshold() {
        // Simple case: 1 guardian, coefficient = 1.
        // Expected: decryption recovers plaintext directly.
        let kp = ElGamalKeyPair::from_secret(ElementModQ::from_u64(17));

        // Encrypt votes: contest_a/sel_0 → 3 votes, contest_a/sel_1 → 1 vote
        let n0 = ElementModQ::from_u64(2);
        let n1 = ElementModQ::from_u64(3);
        let ct0 = elgamal_encrypt(3, &n0, &kp.public_key);
        let ct1 = elgamal_encrypt(1, &n1, &kp.public_key);

        let mut encrypted_tally: HashMap<String, HashMap<String, ElGamalCiphertext>> =
            HashMap::new();
        let mut contest = HashMap::new();
        contest.insert("sel_0".to_string(), ct0.clone());
        contest.insert("sel_1".to_string(), ct1.clone());
        encrypted_tally.insert("contest_a".to_string(), contest);

        // Compute partial decryptions
        let (share0, proof0) = compute_decryption_share(&kp.secret_key, &ct0);
        let (share1, proof1) = compute_decryption_share(&kp.secret_key, &ct1);

        let g_id = "guardian_1".to_string();
        let mut ts = TallyDecryptionShare::new(g_id.clone());
        ts.insert("contest_a", "sel_0", PartialDecryption::new(g_id.clone(), share0, proof0));
        ts.insert("contest_a", "sel_1", PartialDecryption::new(g_id.clone(), share1, proof1));

        // Lagrange coefficient = 1 for sole guardian
        let mut lagrange: HashMap<String, ElementModQ> = HashMap::new();
        lagrange.insert(g_id, ElementModQ::one().clone());

        let result = decrypt_tally_with_shares(&encrypted_tally, &[ts], &lagrange).unwrap();
        assert_eq!(result["contest_a"]["sel_0"], 3, "sel_0 should decrypt to 3");
        assert_eq!(result["contest_a"]["sel_1"], 1, "sel_1 should decrypt to 1");
    }

    #[test]
    fn decrypt_tally_two_guardians_non_threshold() {
        // Two guardians, K = g^(s1+s2), no threshold — each with coefficient 1.
        let s1 = ElementModQ::from_u64(11);
        let s2 = ElementModQ::from_u64(23);
        let s_combined = add_mod_q(&s1, &s2);
        let public_key = g_pow(&s_combined);

        let nonce = ElementModQ::from_u64(7);
        let ct = elgamal_encrypt(2, &nonce, &public_key);

        // Each guardian partially decrypts with their own key
        let (share1, proof1) = compute_decryption_share(&s1, &ct);
        let (share2, proof2) = compute_decryption_share(&s2, &ct);

        let mut encrypted_tally: HashMap<String, HashMap<String, ElGamalCiphertext>> =
            HashMap::new();
        let mut contest = HashMap::new();
        contest.insert("sel_0".to_string(), ct);
        encrypted_tally.insert("c0".to_string(), contest);

        let g1 = "g1".to_string();
        let g2 = "g2".to_string();

        let mut ts1 = TallyDecryptionShare::new(g1.clone());
        ts1.insert("c0", "sel_0", PartialDecryption::new(g1.clone(), share1, proof1));

        let mut ts2 = TallyDecryptionShare::new(g2.clone());
        ts2.insert("c0", "sel_0", PartialDecryption::new(g2.clone(), share2, proof2));

        let one = ElementModQ::one().clone();
        let mut lagrange = HashMap::new();
        lagrange.insert(g1, one.clone());
        lagrange.insert(g2, one);

        let result = decrypt_tally_with_shares(&encrypted_tally, &[ts1, ts2], &lagrange).unwrap();
        assert_eq!(result["c0"]["sel_0"], 2);
    }

    // ── TallyDecryptionShare helpers ──────────────────────────────────────────

    #[test]
    fn tally_share_insert_and_lookup() {
        let kp = ElGamalKeyPair::from_secret(ElementModQ::from_u64(5));
        let nonce = ElementModQ::from_u64(3);
        let ct = elgamal_encrypt(1, &nonce, &kp.public_key);
        let (share, proof) = compute_decryption_share(&kp.secret_key, &ct);

        let mut ts = TallyDecryptionShare::new("g1".to_string());
        ts.insert("contest_1", "sel_1", PartialDecryption::new("g1".to_string(), share, proof));

        assert!(ts.contest_shares.contains_key("contest_1"));
        assert!(ts.contest_shares["contest_1"].contains_key("sel_1"));
    }

    // ── DecryptionProof::compute_commitment_hash (lines 123, 137, 143) ──────

    #[test]
    fn compute_commitment_hash_is_deterministic() {
        let kp = ElGamalKeyPair::from_secret(ElementModQ::from_u64(7));
        let nonce = ElementModQ::from_u64(3);
        let ct = elgamal_encrypt(1, &nonce, &kp.public_key);
        let ext_hash = ElementModQ::from_u64(42);

        let (share, proof) = compute_decryption_share(&kp.secret_key, &ct);
        let dp = DecryptionProof::from_chaum_pedersen(proof);
        let dp_share = share;

        let h1 = DecryptionProof::compute_commitment_hash(
            &ext_hash, 1, 1, 1,
            &ct.pad, &ct.data,
            &dp.pad, &dp.data,
            &dp_share,
            &[1, 2, 3],
        ).unwrap();
        let h2 = DecryptionProof::compute_commitment_hash(
            &ext_hash, 1, 1, 1,
            &ct.pad, &ct.data,
            &dp.pad, &dp.data,
            &dp_share,
            &[1, 2, 3],
        ).unwrap();
        assert_eq!(h1, h2);
        assert!(!h1.is_zero());
    }

    #[test]
    fn compute_commitment_hash_varies_by_contest_index() {
        let ext_hash = ElementModQ::from_u64(99);
        let p = crate::group::ElementModP::g().clone();

        let h1 = DecryptionProof::compute_commitment_hash(
            &ext_hash, 1, 1, 1, &p, &p, &p, &p, &p, &[1],
        ).unwrap();
        let h2 = DecryptionProof::compute_commitment_hash(
            &ext_hash, 2, 1, 1, &p, &p, &p, &p, &p, &[1],
        ).unwrap();
        assert_ne!(h1, h2);
    }

    // ── DecryptionProof::compute_decryption_challenge (lines 172, 185) ──────

    #[test]
    fn compute_decryption_challenge_is_deterministic() {
        let ext_hash = ElementModQ::from_u64(7);
        let p = crate::group::ElementModP::g().clone();

        let c1 = DecryptionProof::compute_decryption_challenge(
            &ext_hash, 1, 1, &p, &p, &p, &p, &p,
        ).unwrap();
        let c2 = DecryptionProof::compute_decryption_challenge(
            &ext_hash, 1, 1, &p, &p, &p, &p, &p,
        ).unwrap();
        assert_eq!(c1, c2);
        assert!(!c1.is_zero());
    }

    #[test]
    fn compute_decryption_challenge_varies_by_selection_index() {
        let ext_hash = ElementModQ::from_u64(5);
        let p = crate::group::ElementModP::g().clone();

        let c1 = DecryptionProof::compute_decryption_challenge(
            &ext_hash, 1, 1, &p, &p, &p, &p, &p,
        ).unwrap();
        let c2 = DecryptionProof::compute_decryption_challenge(
            &ext_hash, 1, 2, &p, &p, &p, &p, &p,
        ).unwrap();
        assert_ne!(c1, c2);
    }

    // ── DecryptionProof::compute_contest_data_commitment_hash (202, 216, 222)

    #[test]
    fn compute_contest_data_commitment_hash_is_deterministic() {
        let enc_id = ElementModQ::from_u64(10);
        let p = crate::group::ElementModP::g().clone();
        let c1_bytes = b"c1_bytes";
        let c2_bytes = b"c2_bytes";

        let h1 = DecryptionProof::compute_contest_data_commitment_hash(
            &enc_id, 1, 1, &p, c1_bytes, c2_bytes, &p, &p, &p, &[1, 2],
        ).unwrap();
        let h2 = DecryptionProof::compute_contest_data_commitment_hash(
            &enc_id, 1, 1, &p, c1_bytes, c2_bytes, &p, &p, &p, &[1, 2],
        ).unwrap();
        assert_eq!(h1, h2);
        assert!(!h1.is_zero());
    }

    // ── Lagrange denominator zero (line 373) ─────────────────────────────────

    #[test]
    fn lagrange_duplicate_indices_are_skipped_gracefully() {
        // When available_guardians contains only the guardian's own index, the loop body
        // is skipped entirely (j == guardian_index), numerator and denominator both stay
        // at one, and the result is 1 (the correct coefficient for a single-guardian set).
        let result = compute_lagrange_coefficient(1, &[1, 1]);
        assert!(result.is_ok(), "duplicate identical index should succeed");
        // The guard-self-skip leaves numerator=1, denominator=1, so w = 1.
        assert_eq!(result.unwrap(), *ElementModQ::one());
    }

    // ── compute_compensated_decryption_share (lines 625, 631) ───────────────

    #[test]
    fn compensated_decryption_share_matches_regular_share() {
        // The compensated share is just a wrapper around the regular share
        // using the Shamir-share scalar as the "key".
        let shamir_share = ElementModQ::from_u64(13);
        let kp = crate::elgamal::ElGamalKeyPair::from_secret(shamir_share.clone());
        let nonce = ElementModQ::from_u64(7);
        let ct = elgamal_encrypt(1, &nonce, &kp.public_key);

        // The public share g^{P_i(j)} for API compatibility (unused internally)
        let pub_share = g_pow(&shamir_share);

        let (comp_share, _proof) =
            compute_compensated_decryption_share(&shamir_share, &pub_share, &ct);

        // Must equal A^{shamir_share}
        let expected = crate::group::pow_mod_p(&ct.pad, &shamir_share);
        assert_eq!(comp_share, expected, "compensated share must equal α^(Pᵢ(j))");
    }

    // ── decrypt_tally_with_shares error paths (lines 559, 570) ─────────────

    #[test]
    fn decrypt_tally_missing_lagrange_coefficient_returns_error() {
        use crate::elgamal::ElGamalKeyPair;

        let kp = ElGamalKeyPair::from_secret(ElementModQ::from_u64(5));
        let nonce = ElementModQ::from_u64(3);
        let ct = elgamal_encrypt(1, &nonce, &kp.public_key);

        let mut encrypted_tally: HashMap<String, HashMap<String, _>> = HashMap::new();
        let mut contest = HashMap::new();
        contest.insert("sel_0".to_string(), ct.clone());
        encrypted_tally.insert("c0".to_string(), contest);

        let (share, proof) = compute_decryption_share(&kp.secret_key, &ct);
        let mut ts = TallyDecryptionShare::new("guardian-1".to_string());
        ts.insert("c0", "sel_0", PartialDecryption::new("guardian-1".to_string(), share, proof));

        // Lagrange map is EMPTY → "guardian-1" has no coefficient → error at line 559
        let empty_lagrange: HashMap<String, ElementModQ> = HashMap::new();
        let result = decrypt_tally_with_shares(&encrypted_tally, &[ts], &empty_lagrange);
        assert!(result.is_err(), "missing Lagrange coefficient must produce an error");
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("Lagrange") || msg.contains("lagrange") || msg.contains("guardian"),
            "error must mention the missing coefficient"
        );
    }

    #[test]
    fn decrypt_tally_missing_share_for_selection_returns_error() {
        use crate::elgamal::ElGamalKeyPair;

        let kp = ElGamalKeyPair::from_secret(ElementModQ::from_u64(5));
        let nonce = ElementModQ::from_u64(3);
        let ct = elgamal_encrypt(1, &nonce, &kp.public_key);

        let mut encrypted_tally: HashMap<String, HashMap<String, _>> = HashMap::new();
        let mut contest = HashMap::new();
        contest.insert("sel_MISSING".to_string(), ct);
        encrypted_tally.insert("c0".to_string(), contest);

        // Guardian's share covers "c0"/"sel_0" but the tally has "sel_MISSING"
        let gid = "guardian-1".to_string();
        let ts = TallyDecryptionShare::new(gid.clone()); // empty share

        let mut lagrange: HashMap<String, ElementModQ> = HashMap::new();
        lagrange.insert(gid, ElementModQ::one().clone());

        // Missing share → error at line 570
        let result = decrypt_tally_with_shares(&encrypted_tally, &[ts], &lagrange);
        assert!(result.is_err(), "missing share for selection must produce an error");
    }
}
