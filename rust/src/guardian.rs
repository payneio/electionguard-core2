//! Guardian key ceremony and Schnorr proof types for ElectionGuard v2.1.
//!
//! Implements:
//! - Schnorr proof of knowledge for discrete logarithm (key ownership)
//! - Polynomial key generation for Shamir's secret sharing
//! - Encrypted partial key backup (share exchange between guardians)
//! - Joint key computation from all guardian public keys
//! - Lagrange coefficient computation for threshold decryption

use rand::rngs::OsRng;

use crate::elgamal::{hashed_elgamal_decrypt, hashed_elgamal_encrypt, HashedElGamalCiphertext};
use crate::error::{Error, Result};
use crate::group::{
    add_mod_q, div_mod_q, g_pow, mul_mod_p, mul_mod_q, pow_mod_p, sub_mod_q, ElementModP,
    ElementModQ,
};
use crate::group::constants::EG_DS_KEY_GENERATION_NIZK;
use crate::hash::{hash_elems_v21, hash_elems_v21_raw, HashableValue};
use crate::nonces::Nonces;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ── SchnorrProof ──────────────────────────────────────────────────────────────

/// Schnorr proof of knowledge of a discrete logarithm.
///
/// Proves knowledge of `s` such that `K = g^s` without revealing `s`.
///
/// Construction:
/// 1. Choose random nonce `w`
/// 2. Commitment `h = g^w`
/// 3. Challenge `c = H(H_P; 0x10, K, h)`
/// 4. Response `u = w - c·s mod Q`
///
/// Verification: `g^u · K^c == h`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchnorrProof {
    /// The public key `K = g^s mod P`.
    pub public_key: ElementModP,
    /// The commitment `h = g^w mod P`.
    pub commitment: ElementModP,
    /// The Fiat-Shamir challenge `c = H(H_P; 0x10, K, h)`.
    pub challenge: ElementModQ,
    /// The response `u = w - c·s mod Q`.
    pub response: ElementModQ,
}

/// A consolidated Schnorr proof covering all polynomial coefficient commitments.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsolidatedSchnorrProof {
    /// One Schnorr proof per polynomial coefficient.
    pub proofs: Vec<SchnorrProof>,
}

// ── GuardianKeyPair ───────────────────────────────────────────────────────────

/// A single ElGamal key pair for a guardian.
///
/// The secret key is zeroized on drop.
pub struct GuardianKeyPair {
    /// Secret key `s ∈ Z_Q`.
    pub secret_key: ElementModQ,
    /// Public key `K = g^s mod P`.
    pub public_key: ElementModP,
}

impl GuardianKeyPair {
    /// Create from a known secret key.
    pub fn from_secret(secret_key: ElementModQ) -> Self {
        let public_key = g_pow(&secret_key);
        Self { secret_key, public_key }
    }

    /// Generate a fresh key pair using the OS RNG.
    pub fn generate() -> Self {
        let secret_key = ElementModQ::random(&mut OsRng);
        Self::from_secret(secret_key)
    }
}

impl Drop for GuardianKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

// ── GuardianKeySet ────────────────────────────────────────────────────────────

/// A guardian's complete key material for a key ceremony.
///
/// Contains:
/// - Vote key pair: used for encrypting ballot votes
/// - Data key pair: used for encrypting ballot contest data
/// - Communication key pair: used for encrypted share exchange
/// - Vote polynomial: Shamir coefficients for the vote secret
/// - Data polynomial: Shamir coefficients for the data secret
pub struct GuardianKeySet {
    /// Human-readable guardian identifier.
    pub owner_id: String,
    /// Guardian's 1-based sequential index.
    pub sequence_order: u32,
    /// Vote encryption key pair (K_i, s_i).
    pub vote_key_pair: GuardianKeyPair,
    /// Data encryption key pair (K̂_i, ŝ_i).
    pub data_key_pair: GuardianKeyPair,
    /// Communication key pair for encrypted share exchange.
    pub comm_key_pair: GuardianKeyPair,
    /// Shamir polynomial coefficients for the vote secret.
    /// `vote_polynomial[0]` is the secret key `s_i`.
    pub vote_polynomial: Vec<ElementModQ>,
    /// Shamir polynomial coefficients for the data secret.
    pub data_polynomial: Vec<ElementModQ>,
}

// ── CoefficientSet ────────────────────────────────────────────────────────────

/// Polynomial coefficients for Shamir's secret sharing.
///
/// The first coefficient is the secret key; remaining coefficients are random.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoefficientSet {
    /// Vote polynomial coefficients `[a_0, a_1, ..., a_{k-1}]`.
    /// `a_0` is the vote secret key; `K_i = g^{a_0}` is the public key.
    pub coefficients: Vec<ElementModQ>,
    /// Data polynomial coefficients `[b_0, b_1, ..., b_{k-1}]`.
    pub data_coefficients: Vec<ElementModQ>,
}

// ── PublicKeySet ──────────────────────────────────────────────────────────────

/// The public portion of a guardian's key set, published after key ceremony.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeySet {
    pub owner_id: String,
    pub sequence_order: u32,
    /// Vote public key `K_i = g^{a_0} mod P`.
    pub vote_key: ElementModP,
    /// Data public key `K̂_i = g^{b_0} mod P`.
    pub data_key: ElementModP,
    /// Schnorr proofs for each vote polynomial coefficient commitment.
    pub vote_proofs: Vec<SchnorrProof>,
    /// Schnorr proofs for each data polynomial coefficient commitment.
    pub data_proofs: Vec<SchnorrProof>,
    /// Public commitments for vote coefficients: `K_{i,j} = g^{a_j}`.
    pub vote_commitments: Vec<ElementModP>,
    /// Public commitments for data coefficients: `K̂_{i,j} = g^{b_j}`.
    pub data_commitments: Vec<ElementModP>,
}

// ── EncryptedShare ────────────────────────────────────────────────────────────

/// An encrypted partial key backup sent from one guardian to another.
///
/// Contains `f_i(j)` (owner i's polynomial evaluated at designated index j),
/// encrypted with the designated guardian's communication public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedShare {
    /// Owner guardian identifier.
    pub owner_id: String,
    /// Designated (recipient) guardian identifier.
    pub designated_id: String,
    /// The encrypted share value: `HashedElGamal(f_i(j), K_comm_j)`.
    pub encrypted_value: HashedElGamalCiphertext,
}

// ── DecryptedShare ────────────────────────────────────────────────────────────

/// A decrypted partial key share `f_i(j)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptedShare {
    /// Owner guardian identifier.
    pub guardian_id: String,
    /// The decrypted share value `f_i(j) ∈ Z_Q`.
    pub value: ElementModQ,
}

// ── GuardianRecord ────────────────────────────────────────────────────────────

/// Public record for a guardian, published after the key ceremony.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianRecord {
    pub guardian_index: u64,
    pub owner_id: String,
    pub vote_public_key: ElementModP,
    pub data_public_key: ElementModP,
    pub vote_schnorr_proof: ConsolidatedSchnorrProof,
    pub data_schnorr_proof: ConsolidatedSchnorrProof,
    /// Hash binding all published material.
    pub record_hash: ElementModQ,
}

// ── Schnorr proof functions ───────────────────────────────────────────────────

/// Generate a Schnorr proof of knowledge for `key_pair.secret_key`.
///
/// The `seed` is used to derive the commitment nonce deterministically.
/// The `parameter_hash` (`H_P`) is used as the HMAC key for the challenge.
pub fn generate_schnorr_proof(
    key_pair: &GuardianKeyPair,
    seed: &ElementModQ,
    parameter_hash: &ElementModQ,
) -> Result<SchnorrProof> {
    let nonces = Nonces::new(seed);
    let w = nonces.get(0)?;

    let commitment = g_pow(&w);

    // c = H(H_P; 0x10, K, h)
    let challenge = hash_elems_v21(
        parameter_hash,
        EG_DS_KEY_GENERATION_NIZK,
        &[
            HashableValue::ModP(&key_pair.public_key),
            HashableValue::ModP(&commitment),
        ],
    )?;

    // u = w - c·s mod Q
    let response = sub_mod_q(&w, &mul_mod_q(&challenge, &key_pair.secret_key));

    Ok(SchnorrProof {
        public_key: key_pair.public_key.clone(),
        commitment,
        challenge,
        response,
    })
}

/// Verify a Schnorr proof.
///
/// Returns `true` if `g^response · K^challenge == commitment` and the
/// challenge was correctly computed.
pub fn verify_schnorr_proof(proof: &SchnorrProof, parameter_hash: &ElementModQ) -> bool {
    // Recompute challenge
    let expected_challenge = match hash_elems_v21(
        parameter_hash,
        EG_DS_KEY_GENERATION_NIZK,
        &[
            HashableValue::ModP(&proof.public_key),
            HashableValue::ModP(&proof.commitment),
        ],
    ) {
        Ok(c) => c,
        Err(_) => return false,
    };

    if expected_challenge != proof.challenge {
        return false;
    }

    // g^response · K^challenge == commitment
    let lhs = mul_mod_p(
        &g_pow(&proof.response),
        &pow_mod_p(&proof.public_key, &proof.challenge),
    );

    lhs == proof.commitment
}

// ── Polynomial evaluation ─────────────────────────────────────────────────────

/// Evaluate a polynomial at point `x = exponent_modifier`.
///
/// `f(x) = ∑_{t=0}^{k-1} coefficients[t] · x^t mod Q`
///
/// When `exponent_modifier == 0`, returns `coefficients[0]` (the secret key).
pub fn compute_polynomial_coordinate(
    exponent_modifier: u32,
    coefficients: &[ElementModQ],
) -> ElementModQ {
    if coefficients.is_empty() {
        return ElementModQ::zero().clone();
    }
    let x = ElementModQ::from_u64(exponent_modifier as u64);
    let mut result = ElementModQ::zero().clone();
    let mut x_pow = ElementModQ::one().clone(); // x^0 = 1

    for coeff in coefficients {
        result = add_mod_q(&result, &mul_mod_q(coeff, &x_pow));
        x_pow = mul_mod_q(&x_pow, &x);
    }

    result
}

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate a complete guardian key set for the key ceremony.
///
/// Creates vote and data polynomial coefficients with `quorum` terms.
/// The zeroth coefficient of each polynomial is the corresponding secret key.
///
/// # Arguments
/// * `owner_id`       — Human-readable guardian identifier.
/// * `sequence_order` — 1-based guardian index.
/// * `quorum`         — Polynomial degree (threshold k).
/// * `nonce_seed`     — Deterministic seed; use random `ElementModQ` in production.
pub fn generate_election_key_pair(
    owner_id: &str,
    sequence_order: u32,
    quorum: u32,
    nonce_seed: &ElementModQ,
) -> Result<(GuardianKeySet, CoefficientSet, PublicKeySet)> {
    let nonces = Nonces::new(nonce_seed);

    // Vote polynomial coefficients a_0, a_1, ..., a_{k-1}
    let mut vote_coeffs: Vec<ElementModQ> = Vec::with_capacity(quorum as usize);
    for i in 0..(quorum as u64) {
        vote_coeffs.push(nonces.get(i)?);
    }

    // Data polynomial coefficients b_0, b_1, ..., b_{k-1}
    let mut data_coeffs: Vec<ElementModQ> = Vec::with_capacity(quorum as usize);
    for i in 0..(quorum as u64) {
        data_coeffs.push(nonces.get(quorum as u64 + i)?);
    }

    // Communication key (separate from polynomials)
    let comm_secret = nonces.get(2 * quorum as u64)?;
    let comm_key_pair = GuardianKeyPair::from_secret(comm_secret);

    // Key pairs from zeroth coefficients
    let vote_key_pair = GuardianKeyPair::from_secret(vote_coeffs[0].clone());
    let data_key_pair = GuardianKeyPair::from_secret(data_coeffs[0].clone());

    let vote_key = vote_key_pair.public_key.clone();
    let data_key = data_key_pair.public_key.clone();

    // Public polynomial commitments K_{i,t} = g^{a_t} and K̂_{i,t} = g^{b_t}
    let vote_commitments: Vec<ElementModP> = vote_coeffs.iter().map(g_pow).collect();
    let data_commitments: Vec<ElementModP> = data_coeffs.iter().map(g_pow).collect();

    let key_set = GuardianKeySet {
        owner_id: owner_id.to_string(),
        sequence_order,
        vote_key_pair,
        data_key_pair,
        comm_key_pair,
        vote_polynomial: vote_coeffs.clone(),
        data_polynomial: data_coeffs.clone(),
    };

    let coeff_set = CoefficientSet {
        coefficients: vote_coeffs,
        data_coefficients: data_coeffs,
    };

    let public_key_set = PublicKeySet {
        owner_id: owner_id.to_string(),
        sequence_order,
        vote_key,
        data_key,
        vote_proofs: vec![], // Populated separately via generate_guardian_proofs
        data_proofs: vec![],
        vote_commitments,
        data_commitments,
    };

    Ok((key_set, coeff_set, public_key_set))
}

/// Generate Schnorr proofs for all polynomial coefficients of a guardian.
///
/// Returns `(vote_proofs, data_proofs)` where each vec has `quorum` proofs.
pub fn generate_guardian_proofs(
    key_set: &GuardianKeySet,
    parameter_hash: &ElementModQ,
    nonce_seed: &ElementModQ,
) -> Result<(ConsolidatedSchnorrProof, ConsolidatedSchnorrProof)> {
    let nonces = Nonces::new(nonce_seed);

    let vote_proofs: Result<Vec<SchnorrProof>> = key_set
        .vote_polynomial
        .iter()
        .enumerate()
        .map(|(t, coeff)| {
            let seed = nonces.get(t as u64)?;
            let kp = GuardianKeyPair::from_secret(coeff.clone());
            generate_schnorr_proof(&kp, &seed, parameter_hash)
        })
        .collect();

    let data_proofs: Result<Vec<SchnorrProof>> = key_set
        .data_polynomial
        .iter()
        .enumerate()
        .map(|(t, coeff)| {
            let seed = nonces.get(100 + t as u64)?;
            let kp = GuardianKeyPair::from_secret(coeff.clone());
            generate_schnorr_proof(&kp, &seed, parameter_hash)
        })
        .collect();

    Ok((
        ConsolidatedSchnorrProof { proofs: vote_proofs? },
        ConsolidatedSchnorrProof { proofs: data_proofs? },
    ))
}

// ── Share generation / verification ──────────────────────────────────────────

/// Derive the selection-encryption identifier used for share encryption.
///
/// This creates a deterministic context value that binds the share to the
/// specific (owner, designated) guardian pair.
fn share_selection_enc_id(owner_id: &str, designated_id: &str) -> Result<ElementModQ> {
    use crate::group::constants::EG_DS_SHARE_ENC_KEY;
    let zero_key = [0u8; 32];
    hash_elems_v21_raw(
        &zero_key,
        EG_DS_SHARE_ENC_KEY,
        &[HashableValue::Str(owner_id), HashableValue::Str(designated_id)],
    )
}

/// Generate an encrypted partial key backup for a designated guardian.
///
/// Evaluates owner's vote polynomial at `designated_sequence_order` to obtain
/// `f_i(j)`, then encrypts it using the designated guardian's communication
/// public key.
///
/// # Arguments
/// * `owner_id`                  — Owner guardian identifier.
/// * `designated_id`             — Designated guardian identifier.
/// * `designated_sequence_order` — Designated guardian's 1-based index `j`.
/// * `coefficients`              — Owner's vote polynomial coefficients.
/// * `comm_public_key`           — Designated guardian's communication public key.
pub fn generate_election_partial_key_backup(
    owner_id: &str,
    designated_id: &str,
    designated_sequence_order: u32,
    coefficients: &[ElementModQ],
    comm_public_key: &ElementModP,
) -> Result<EncryptedShare> {
    // Evaluate f_i(j)
    let share_value = compute_polynomial_coordinate(designated_sequence_order, coefficients);

    // Encode as 32 bytes
    let message = share_value.to_bytes_be();

    // Deterministic nonce (for testing) derived from context
    let sel_enc_id = share_selection_enc_id(owner_id, designated_id)?;
    let nonce_seed = hash_elems_v21(
        &sel_enc_id,
        0x00,
        &[HashableValue::U64(designated_sequence_order as u64)],
    )?;
    let nonce = Nonces::new(&nonce_seed).get(0)?;

    let encrypted_value = hashed_elgamal_encrypt(
        &message,
        &nonce,
        comm_public_key,
        &sel_enc_id,
        designated_sequence_order as u64,
        false,
    )?;

    Ok(EncryptedShare {
        owner_id: owner_id.to_string(),
        designated_id: designated_id.to_string(),
        encrypted_value,
    })
}

/// Decrypt a received partial key backup and verify it against the owner's
/// public polynomial commitments.
///
/// # Arguments
/// * `share`               — The encrypted share to verify.
/// * `comm_secret_key`     — Designated guardian's communication secret key.
/// * `designated_seq`      — Designated guardian's 1-based sequence order.
/// * `public_commitments`  — Owner's public polynomial commitments
///   `K_{i,t} = g^{a_t}` for `t = 0..quorum`.
pub fn verify_election_partial_key_backup(
    share: &EncryptedShare,
    comm_secret_key: &ElementModQ,
    designated_seq: u32,
    public_commitments: &[ElementModP],
) -> Result<bool> {
    // Decrypt the share
    let sel_enc_id = share_selection_enc_id(&share.owner_id, &share.designated_id)?;

    let message = hashed_elgamal_decrypt(
        &share.encrypted_value,
        comm_secret_key,
        &sel_enc_id,
        designated_seq as u64,
    )?;

    if message.len() != 32 {
        return Ok(false);
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&message);
    let share_value = ElementModQ::from_bytes_be(&bytes)?;

    // Compute expected: g^{f_i(j)} = ∏ K_{i,t}^{j^t}
    let j = ElementModQ::from_u64(designated_seq as u64);
    let mut expected = ElementModP::one().clone();
    let mut j_pow = ElementModQ::one().clone(); // j^0 = 1

    for commitment in public_commitments {
        // expected *= commitment^{j^t}
        let factor = pow_mod_p(commitment, &j_pow);
        expected = mul_mod_p(&expected, &factor);
        j_pow = mul_mod_q(&j_pow, &j);
    }

    // Verify g^{share_value} == expected
    let actual = g_pow(&share_value);
    Ok(actual == expected)
}

/// Decrypt a received partial key backup, returning the raw share value.
///
/// Use this when you need the raw `f_i(j)` value for threshold operations.
pub fn decrypt_share(
    share: &EncryptedShare,
    comm_secret_key: &ElementModQ,
    designated_seq: u32,
) -> Result<DecryptedShare> {
    let sel_enc_id = share_selection_enc_id(&share.owner_id, &share.designated_id)?;

    let message = hashed_elgamal_decrypt(
        &share.encrypted_value,
        comm_secret_key,
        &sel_enc_id,
        designated_seq as u64,
    )?;

    if message.len() != 32 {
        return Err(Error::InvalidGuardian(
            "decrypted share has wrong length".to_string(),
        ));
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&message);
    let value = ElementModQ::from_bytes_be(&bytes)?;

    Ok(DecryptedShare {
        guardian_id: share.owner_id.clone(),
        value,
    })
}

// ── Joint key ─────────────────────────────────────────────────────────────────

/// Compute the joint election public key from all guardian vote public keys.
///
/// `K = ∏ K_i mod P`
pub fn compute_joint_key(public_keys: &[ElementModP]) -> ElementModP {
    if public_keys.is_empty() {
        return ElementModP::one().clone();
    }
    let mut joint = public_keys[0].clone();
    for key in &public_keys[1..] {
        joint = mul_mod_p(&joint, key);
    }
    joint
}

/// Compute the joint election public key from a slice of references.
pub fn compute_joint_key_refs(public_keys: &[&ElementModP]) -> ElementModP {
    if public_keys.is_empty() {
        return ElementModP::one().clone();
    }
    let mut joint = (*public_keys[0]).clone();
    for key in &public_keys[1..] {
        joint = mul_mod_p(&joint, key);
    }
    joint
}

/// Compute the commitment hash `Ĥ` from all guardian polynomial commitments.
///
/// `Ĥ = H(H_B; 0x12, K_{1,0}, ..., K_{n,k-1}, K̂_{1,0}, ..., K̂_{n,k-1})`
pub fn compute_commitment_hash(
    base_hash: &ElementModQ,
    vote_commitments: &[Vec<ElementModP>],
    data_commitments: &[Vec<ElementModP>],
) -> Result<ElementModQ> {
    use crate::group::constants::EG_DS_SHARE_ENC_PROOF;

    let mut args: Vec<HashableValue<'_>> = Vec::new();
    for guardian_commitments in vote_commitments {
        for c in guardian_commitments {
            args.push(HashableValue::ModP(c));
        }
    }
    for guardian_commitments in data_commitments {
        for c in guardian_commitments {
            args.push(HashableValue::ModP(c));
        }
    }

    hash_elems_v21(base_hash, EG_DS_SHARE_ENC_PROOF, &args)
}

// ── Lagrange coefficient ──────────────────────────────────────────────────────

/// Compute the Lagrange interpolation coefficient for guardian `my_seq`
/// among the set `others` (which should include `my_seq`).
///
/// ```text
/// w_i = ∏_{j ∈ S, j ≠ i}  j / (j - i)  mod Q
/// ```
///
/// # Arguments
/// * `my_seq` — The guardian's sequence order (1-based).
/// * `others` — All guardian sequence orders in the quorum (including `my_seq`).
pub fn compute_lagrange_coefficient(my_seq: u32, others: &[u32]) -> Result<ElementModQ> {
    // Guardian must be in the participating set.
    if !others.contains(&my_seq) {
        return Err(Error::Arithmetic(format!(
            "guardian {} is not in the available set {:?}",
            my_seq, others
        )));
    }

    let i = ElementModQ::from_u64(my_seq as u64);

    let mut numerator = ElementModQ::one().clone();
    let mut denominator = ElementModQ::one().clone();

    for &j in others {
        if j == my_seq {
            continue;
        }
        let j_q = ElementModQ::from_u64(j as u64);
        numerator = mul_mod_q(&numerator, &j_q);
        let diff = sub_mod_q(&j_q, &i);
        denominator = mul_mod_q(&denominator, &diff);
    }

    // w_i = numerator / denominator mod Q
    div_mod_q(&numerator, &denominator)
}

/// Build a `GuardianRecord` for publication after the key ceremony.
pub fn build_guardian_record(
    key_set: &GuardianKeySet,
    base_hash: &ElementModQ,
    parameter_hash: &ElementModQ,
) -> Result<GuardianRecord> {
    // Generate proofs seeded from the key set's vote secret
    let proof_seed = hash_elems_v21(
        parameter_hash,
        0x00,
        &[HashableValue::ModP(&key_set.vote_key_pair.public_key)],
    )?;
    let (vote_proof, data_proof) =
        generate_guardian_proofs(key_set, parameter_hash, &proof_seed)?;

    // Record hash: H(H_B; 0x14, K_i, K̂_i)
    use crate::group::constants::EG_DS_GUARDIAN_RECORD_HASH;
    let record_hash = hash_elems_v21(
        base_hash,
        EG_DS_GUARDIAN_RECORD_HASH,
        &[
            HashableValue::ModP(&key_set.vote_key_pair.public_key),
            HashableValue::ModP(&key_set.data_key_pair.public_key),
        ],
    )?;

    Ok(GuardianRecord {
        guardian_index: key_set.sequence_order as u64,
        owner_id: key_set.owner_id.clone(),
        vote_public_key: key_set.vote_key_pair.public_key.clone(),
        data_public_key: key_set.data_key_pair.public_key.clone(),
        vote_schnorr_proof: vote_proof,
        data_schnorr_proof: data_proof,
        record_hash,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::election::compute_parameter_hash;

    fn seed(n: u64) -> ElementModQ {
        ElementModQ::from_u64(n)
    }

    #[test]
    fn schnorr_proof_generate_and_verify() {
        let parameter_hash = compute_parameter_hash().unwrap();
        let secret = ElementModQ::from_u64(42);
        let kp = GuardianKeyPair::from_secret(secret.clone());
        let proof = generate_schnorr_proof(&kp, &seed(1), &parameter_hash).unwrap();
        assert!(verify_schnorr_proof(&proof, &parameter_hash));
    }

    #[test]
    fn schnorr_proof_wrong_key_fails() {
        let parameter_hash = compute_parameter_hash().unwrap();
        let kp = GuardianKeyPair::from_secret(ElementModQ::from_u64(42));
        let mut proof = generate_schnorr_proof(&kp, &seed(1), &parameter_hash).unwrap();
        // Tamper with the public key
        proof.public_key = g_pow(&ElementModQ::from_u64(99));
        assert!(!verify_schnorr_proof(&proof, &parameter_hash));
    }

    #[test]
    fn polynomial_evaluation_at_zero_is_constant() {
        let coeffs = vec![
            ElementModQ::from_u64(7),
            ElementModQ::from_u64(3),
            ElementModQ::from_u64(2),
        ];
        let at_zero = compute_polynomial_coordinate(0, &coeffs);
        assert_eq!(at_zero, ElementModQ::from_u64(7), "f(0) must equal a_0");
    }

    #[test]
    fn polynomial_evaluation_at_one_is_sum() {
        let coeffs = vec![
            ElementModQ::from_u64(7),
            ElementModQ::from_u64(3),
            ElementModQ::from_u64(2),
        ];
        let at_one = compute_polynomial_coordinate(1, &coeffs);
        // f(1) = 7 + 3 + 2 = 12
        assert_eq!(at_one, ElementModQ::from_u64(12));
    }

    #[test]
    fn polynomial_evaluation_matches_formula() {
        // f(x) = 5 + 3x + 2x^2
        let coeffs = vec![
            ElementModQ::from_u64(5),
            ElementModQ::from_u64(3),
            ElementModQ::from_u64(2),
        ];
        // f(2) = 5 + 6 + 8 = 19
        let at_two = compute_polynomial_coordinate(2, &coeffs);
        assert_eq!(at_two, ElementModQ::from_u64(19));
    }
}
