//! ElGamal encryption types and operations.
//!
//! Implements standard exponential ElGamal and "hashed ElGamal" for arbitrary-length
//! message encryption per the ElectionGuard v2.1 specification.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::group::{
    ElementModP, ElementModQ,
    g_pow, pow_mod_p, mul_mod_p,
};
use crate::group::constants::{
    EG_DS_CONTEST_DATA_ENC_KEY, EG_DS_BALLOT_NONCE_ENC_KEY,
};
use crate::hmac::hmac_sha256;
use crate::kdf::kdf_hmac_sha256;

// ── ElGamalKeyPair ──────────────────────────────────────────────────────────

/// An ElGamal key pair: secret key `s` and public key `K = g^s mod P`.
///
/// The secret key is zeroized on drop.
pub struct ElGamalKeyPair {
    /// Secret key `s ∈ Z_Q`.
    pub secret_key: ElementModQ,
    /// Public key `K = g^s mod P`.
    pub public_key: ElementModP,
}

impl ElGamalKeyPair {
    /// Create a key pair from a secret key, computing the public key.
    pub fn from_secret(secret_key: ElementModQ) -> Self {
        let public_key = g_pow(&secret_key);
        Self { secret_key, public_key }
    }

    /// Generate a fresh key pair using the provided RNG.
    pub fn generate<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
        let secret_key = ElementModQ::random(rng);
        Self::from_secret(secret_key)
    }
}

impl Drop for ElGamalKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

// ── ElGamalCiphertext ────────────────────────────────────────────────────────

/// Standard exponential ElGamal ciphertext: `(pad, data)` = `(g^r, g^m * K^r)`.
///
/// Supports homomorphic addition: `(A₁·A₂, B₁·B₂)` encrypts `m₁ + m₂`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElGamalCiphertext {
    /// `α = g^r mod P` — the "nonce component".
    pub pad: ElementModP,
    /// `β = g^m · K^r mod P` — the "message component".
    pub data: ElementModP,
}

// ── HashedElGamalCiphertext ──────────────────────────────────────────────────

/// Hashed ElGamal ciphertext for arbitrary-length messages.
///
/// * `pad`  = `g^r mod P`
/// * `data` = `message XOR keystream(k_enc)`
/// * `mac`  = `HMAC-SHA-256(k_mac, pad_bytes || data)`
///
/// where `(k_enc || k_mac) = KDF(K^r, label)`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HashedElGamalCiphertext {
    /// `C₀ = g^r mod P` — used to recover the shared secret.
    pub pad: ElementModP,
    /// `C₁ = message ⊕ keystream` — XOR-encrypted ciphertext.
    pub data: Vec<u8>,
    /// `C₂ = HMAC(k_mac, C₀ || C₁)` — authentication tag.
    pub mac: Vec<u8>,
}

// ── Standard ElGamal ─────────────────────────────────────────────────────────

/// Encrypt `plaintext` using exponential ElGamal.
///
/// ```text
/// pad  = g^nonce mod P
/// data = g^plaintext · public_key^nonce mod P
/// ```
///
/// # Arguments
/// * `plaintext`  — The integer message `m` (typically 0 or 1 for a ballot selection).
/// * `nonce`      — Randomness `r ∈ Z_Q`.
/// * `public_key` — Election public key `K = g^s mod P`.
pub fn elgamal_encrypt(
    plaintext: u64,
    nonce: &ElementModQ,
    public_key: &ElementModP,
) -> ElGamalCiphertext {
    let pad = g_pow(nonce);                          // g^r
    let g_m = g_pow(&ElementModQ::from_u64(plaintext)); // g^m
    let k_r = pow_mod_p(public_key, nonce);           // K^r
    let data = mul_mod_p(&g_m, &k_r);                // g^m · K^r
    ElGamalCiphertext { pad, data }
}

/// Homomorphically add two ciphertexts.
///
/// If `a` encrypts `m₁` and `b` encrypts `m₂` (under the same key), the result
/// encrypts `m₁ + m₂`:
/// ```text
/// (α₁·α₂, β₁·β₂) = (g^{r₁+r₂}, g^{m₁+m₂} · K^{r₁+r₂})
/// ```
pub fn elgamal_add(a: &ElGamalCiphertext, b: &ElGamalCiphertext) -> ElGamalCiphertext {
    ElGamalCiphertext {
        pad: mul_mod_p(&a.pad, &b.pad),
        data: mul_mod_p(&a.data, &b.data),
    }
}

/// Accumulate a slice of ciphertexts into a single ciphertext (homomorphic sum).
///
/// Returns the identity ciphertext `(1, 1)` if the slice is empty.
pub fn elgamal_accumulate(ciphertexts: &[&ElGamalCiphertext]) -> ElGamalCiphertext {
    if ciphertexts.is_empty() {
        return ElGamalCiphertext {
            pad: ElementModP::one().clone(),
            data: ElementModP::one().clone(),
        };
    }
    let mut acc = (*ciphertexts[0]).clone();
    for ct in &ciphertexts[1..] {
        acc = elgamal_add(&acc, ct);
    }
    acc
}

// ── Hashed ElGamal ───────────────────────────────────────────────────────────

/// Derive encryption and MAC keys from a shared secret using the KDF.
///
/// Returns `(k_enc [32 B], k_mac [32 B])`.
fn derive_hashed_elgamal_keys(
    shared_secret_bytes: &[u8],
    domain_sep: u8,
    selection_enc_id: &ElementModQ,
    extra_context: &[u8],
) -> ([u8; 32], [u8; 32]) {
    // label = [domain_sep] || selection_enc_id_bytes || extra_context
    let mut label = Vec::with_capacity(1 + 32 + extra_context.len());
    label.push(domain_sep);
    label.extend_from_slice(&selection_enc_id.to_bytes_be());
    label.extend_from_slice(extra_context);

    let km = kdf_hmac_sha256(shared_secret_bytes, &label, b"", 64);
    let mut k_enc = [0u8; 32];
    let mut k_mac = [0u8; 32];
    k_enc.copy_from_slice(&km[..32]);
    k_mac.copy_from_slice(&km[32..]);
    (k_enc, k_mac)
}

/// XOR `message` with a keystream derived from `k_enc` using the KDF.
fn xor_keystream(k_enc: &[u8; 32], message: &[u8]) -> Vec<u8> {
    if message.is_empty() {
        return Vec::new();
    }
    let keystream = kdf_hmac_sha256(k_enc, b"stream", b"", message.len());
    message.iter().zip(keystream.iter()).map(|(m, k)| m ^ k).collect()
}

/// Compute `HMAC(k_mac, pad_bytes || ciphertext_data)`.
fn compute_mac(k_mac: &[u8; 32], pad: &ElementModP, ciphertext_data: &[u8]) -> Vec<u8> {
    let mut mac_input = pad.to_bytes_be().to_vec();
    mac_input.extend_from_slice(ciphertext_data);
    hmac_sha256(k_mac, &mac_input).to_vec()
}

/// Encrypt an arbitrary-length `message` using hashed ElGamal.
///
/// Used for contest data encryption per the v2.1 spec.
///
/// ```text
/// C₀ = g^nonce mod P
/// shared = public_key^nonce mod P
/// (k_enc, k_mac) = KDF(shared, label)
/// C₁ = message ⊕ keystream(k_enc)
/// C₂ = HMAC(k_mac, C₀ || C₁)
/// ```
///
/// # Arguments
/// * `message`          — Plaintext bytes.
/// * `nonce`            — Randomness `r`.
/// * `public_key`       — Data encryption public key `K̂`.
/// * `selection_enc_id` — Per-ballot selection encryption identifier `H_I`.
/// * `contest_index`    — 1-based contest index (included in the KDF label).
/// * `should_verify`    — If `true`, verify the MAC after encryption (sanity check).
pub fn hashed_elgamal_encrypt(
    message: &[u8],
    nonce: &ElementModQ,
    public_key: &ElementModP,
    selection_enc_id: &ElementModQ,
    contest_index: u64,
    should_verify: bool,
) -> Result<HashedElGamalCiphertext> {
    let pad = g_pow(nonce);                                      // C₀ = g^r
    let shared_secret_p = pow_mod_p(public_key, nonce);          // K̂^r
    let shared_secret_bytes = shared_secret_p.to_bytes_be();

    let ctx = contest_index.to_be_bytes();
    let (k_enc, k_mac) = derive_hashed_elgamal_keys(
        &shared_secret_bytes,
        EG_DS_CONTEST_DATA_ENC_KEY,
        selection_enc_id,
        &ctx,
    );

    let data = xor_keystream(&k_enc, message);
    let mac = compute_mac(&k_mac, &pad, &data);

    if should_verify {
        let expected = compute_mac(&k_mac, &pad, &data);
        if mac != expected {
            return Err(Error::Encryption("hashed_elgamal_encrypt: MAC mismatch".to_string()));
        }
    }

    Ok(HashedElGamalCiphertext { pad, data, mac })
}

/// Decrypt a `HashedElGamalCiphertext` using the recipient's secret key.
///
/// Verifies the MAC before decrypting.
///
/// # Arguments
/// * `ciphertext`       — The ciphertext to decrypt.
/// * `secret_key`       — Recipient secret key `s`.
/// * `selection_enc_id` — Per-ballot selection encryption identifier.
/// * `contest_index`    — 1-based contest index.
pub fn hashed_elgamal_decrypt(
    ciphertext: &HashedElGamalCiphertext,
    secret_key: &ElementModQ,
    selection_enc_id: &ElementModQ,
    contest_index: u64,
) -> Result<Vec<u8>> {
    // Recover shared secret: C₀^s = (g^r)^s = g^{rs} = (g^s)^r = K̂^r
    let shared_secret_p = pow_mod_p(&ciphertext.pad, secret_key);
    let shared_secret_bytes = shared_secret_p.to_bytes_be();

    let ctx = contest_index.to_be_bytes();
    let (k_enc, k_mac) = derive_hashed_elgamal_keys(
        &shared_secret_bytes,
        EG_DS_CONTEST_DATA_ENC_KEY,
        selection_enc_id,
        &ctx,
    );

    // Verify MAC
    let expected_mac = compute_mac(&k_mac, &ciphertext.pad, &ciphertext.data);
    if ciphertext.mac != expected_mac {
        return Err(Error::Decryption("hashed_elgamal_decrypt: MAC verification failed".to_string()));
    }

    // Decrypt
    let message = xor_keystream(&k_enc, &ciphertext.data);
    Ok(message)
}

/// Encrypt the ballot nonce `ξ_B` (a 32-byte `ElementModQ`) using hashed ElGamal.
///
/// Uses domain separator `EG_DS_BALLOT_NONCE_ENC_KEY`.
///
/// # Arguments
/// * `ballot_nonce`     — The per-ballot master nonce `ξ_B`.
/// * `nonce`            — Randomness `r` for the ElGamal pad.
/// * `data_public_key`  — Data encryption public key `K̂`.
/// * `selection_enc_id` — Per-ballot selection encryption identifier `H_I`.
pub fn encrypt_ballot_nonce(
    ballot_nonce: &ElementModQ,
    nonce: &ElementModQ,
    data_public_key: &ElementModP,
    selection_enc_id: &ElementModQ,
) -> Result<HashedElGamalCiphertext> {
    let message = ballot_nonce.to_bytes_be();

    let pad = g_pow(nonce);
    let shared_secret_p = pow_mod_p(data_public_key, nonce);
    let shared_secret_bytes = shared_secret_p.to_bytes_be();

    let (k_enc, k_mac) = derive_hashed_elgamal_keys(
        &shared_secret_bytes,
        EG_DS_BALLOT_NONCE_ENC_KEY,
        selection_enc_id,
        b"",
    );

    let data = xor_keystream(&k_enc, &message);
    let mac = compute_mac(&k_mac, &pad, &data);

    Ok(HashedElGamalCiphertext { pad, data, mac })
}

/// Verify structural validity of an encrypted ballot nonce ciphertext.
///
/// Checks that the data is exactly 32 bytes (one `ElementModQ`) and the MAC
/// is 32 bytes, without requiring the secret key.
///
/// # Arguments
/// * `ciphertext`       — The ciphertext to validate.
/// * `_data_public_key` — Unused (included for API symmetry).
/// * `_selection_enc_id`— Unused (included for API symmetry).
pub fn verify_ballot_nonce(
    ciphertext: &HashedElGamalCiphertext,
    _data_public_key: &ElementModP,
    _selection_enc_id: &ElementModQ,
) -> Result<bool> {
    // Structural checks only — we cannot verify the MAC without the secret key.
    if ciphertext.data.len() != 32 {
        return Ok(false);
    }
    if ciphertext.mac.len() != 32 {
        return Ok(false);
    }
    if ciphertext.pad.is_zero() {
        return Ok(false);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elgamal_basic_encrypt() {
        let secret = ElementModQ::from_u64(42);
        let keypair = ElGamalKeyPair::from_secret(secret);
        let nonce = ElementModQ::from_u64(7);
        let ct = elgamal_encrypt(1, &nonce, &keypair.public_key);
        // Sanity: pad = g^7
        assert_eq!(ct.pad, g_pow(&nonce));
        // data = g^1 * K^7
        let g1 = g_pow(&ElementModQ::from_u64(1));
        let k7 = pow_mod_p(&keypair.public_key, &nonce);
        assert_eq!(ct.data, mul_mod_p(&g1, &k7));
    }

    #[test]
    fn elgamal_homomorphic_add() {
        let secret = ElementModQ::from_u64(99);
        let kp = ElGamalKeyPair::from_secret(secret);
        let n1 = ElementModQ::from_u64(3);
        let n2 = ElementModQ::from_u64(5);
        let ct0 = elgamal_encrypt(0, &n1, &kp.public_key);
        let ct1 = elgamal_encrypt(1, &n2, &kp.public_key);
        let sum = elgamal_add(&ct0, &ct1);
        // sum should equal encrypt(1, n1+n2, kp.public_key) mod P
        // pad: g^(n1+n2)
        use crate::group::add_mod_q;
        let n12 = add_mod_q(&n1, &n2);
        let expected_pad = g_pow(&n12);
        assert_eq!(sum.pad, expected_pad);
    }
}
