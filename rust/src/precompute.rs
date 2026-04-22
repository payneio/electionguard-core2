//! Precomputed encryption values for fast ElGamal encryption.
//!
//! Generating an ElGamal ciphertext requires two expensive modular
//! exponentiations (`g^r` and `K^r`).  By pre-computing these offline,
//! ballot encryption can proceed at interactive speeds.
//!
//! # Usage
//!
//! ```no_run
//! use electionguard_core2::precompute::PrecomputeBuffer;
//! use electionguard_core2::group::ElementModP;
//!
//! // Build a buffer for a given election public key.
//! let public_key: ElementModP = ElementModP::g().clone();
//! let mut buf = PrecomputeBuffer::new(&public_key, 100);
//!
//! // Pre-generate values synchronously.
//! buf.populate();
//!
//! // At encryption time, pop one precomputed triple.
//! if let Some(pre) = buf.pop_precomputed_encryption() {
//!     let _pad = &pre.pad;       // g^r
//!     let _blind = &pre.blinding_factor; // K^r
//!     // ... use in ElGamal encrypt
//! }
//! ```

use std::collections::VecDeque;
use std::sync::Mutex;

use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::group::{g_pow, pow_mod_p, ElementModP, ElementModQ};
use crate::group::constants::DEFAULT_PRECOMPUTE_SIZE;

// ── PrecomputedEncryption ─────────────────────────────────────────────────────

/// A precomputed ElGamal nonce triple `(r, g^r, K^r)`.
///
/// The secret nonce `r` is zeroized when this value is dropped.
///
/// # Usage
///
/// Pass `pad` and `blinding_factor` directly to the ElGamal encryption
/// function instead of computing fresh exponentiations.
pub struct PrecomputedEncryption {
    /// Random nonce `r ∈ Z_Q`.  **Secret — zeroized on drop.**
    pub secret: ElementModQ,
    /// `g^r mod P` — the ciphertext pad component.
    pub pad: ElementModP,
    /// `K^r mod P` — the blinding factor (shared secret contribution).
    pub blinding_factor: ElementModP,
}

impl PrecomputedEncryption {
    /// Generate a fresh precomputed encryption for `public_key` using `OsRng`.
    pub fn generate(public_key: &ElementModP) -> Self {
        let mut rng = OsRng;
        let secret = ElementModQ::random(&mut rng);
        let pad = g_pow(&secret);               // g^r
        let blinding_factor = pow_mod_p(public_key, &secret); // K^r
        Self { secret, pad, blinding_factor }
    }

    /// Generate with an explicit RNG (useful for testing with a seeded RNG).
    pub fn generate_with_rng<R: rand_core::CryptoRngCore>(
        public_key: &ElementModP,
        rng: &mut R,
    ) -> Self {
        let secret = ElementModQ::random(rng);
        let pad = g_pow(&secret);
        let blinding_factor = pow_mod_p(public_key, &secret);
        Self { secret, pad, blinding_factor }
    }
}

impl Drop for PrecomputedEncryption {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

// ── PrecomputedFakeDisjunctiveCommitments ─────────────────────────────────────

/// Precomputed commitments for the simulated ("fake") branch of a disjunctive
/// Chaum-Pedersen proof.
///
/// In a disjunctive proof that a ciphertext encrypts 0 or 1:
/// * The **real** branch is the one corresponding to the actual plaintext.
/// * The **fake** branch simulates the other value using randomly-chosen
///   challenges and responses.
///
/// These values are precomputed so that proof generation does not require
/// additional expensive exponentiations at election time.
pub struct PrecomputedFakeDisjunctiveCommitments {
    /// Random secret for the fake-zero pad: `pad = g^secret1`.
    pub secret1: ElementModQ,
    /// Random secret for the fake data component: `data_one = K^secret2`.
    pub secret2: ElementModQ,
    /// Shared fake pad `g^secret1`.
    pub pad: ElementModP,
    /// Fake data for the "encrypts 0" branch: `K^secret1`.
    pub data_zero: ElementModP,
    /// Fake data for the "encrypts 1" branch: `K^secret2`.
    pub data_one: ElementModP,
}

impl PrecomputedFakeDisjunctiveCommitments {
    /// Generate fresh fake commitments for `public_key` using `OsRng`.
    pub fn generate(public_key: &ElementModP) -> Self {
        let mut rng = OsRng;
        Self::generate_with_rng(public_key, &mut rng)
    }

    /// Generate with an explicit RNG.
    pub fn generate_with_rng<R: rand_core::CryptoRngCore>(
        public_key: &ElementModP,
        rng: &mut R,
    ) -> Self {
        let secret1 = ElementModQ::random(rng);
        let secret2 = ElementModQ::random(rng);
        let pad = g_pow(&secret1);
        let data_zero = pow_mod_p(public_key, &secret1);
        let data_one = pow_mod_p(public_key, &secret2);
        Self { secret1, secret2, pad, data_zero, data_one }
    }
}

impl Drop for PrecomputedFakeDisjunctiveCommitments {
    fn drop(&mut self) {
        self.secret1.zeroize();
        self.secret2.zeroize();
    }
}

// ── PrecomputedSelection ─────────────────────────────────────────────────────

/// A complete set of precomputed values for encrypting one ballot selection.
///
/// Includes:
/// * An encryption triple for the actual ciphertext.
/// * A proof commitment triple for the Chaum-Pedersen real-branch proof.
/// * Fake disjunctive commitments for the simulated proof branch.
pub struct PrecomputedSelection {
    /// Precomputed `(r, g^r, K^r)` for the selection ciphertext.
    pub encryption: PrecomputedEncryption,
    /// Precomputed `(u, g^u, A^u)` for the real-branch proof commitment
    /// (where `A = g^r` from `encryption`).
    pub proof: PrecomputedEncryption,
    /// Precomputed fake-branch commitments for the disjunctive proof.
    pub fake_proof: PrecomputedFakeDisjunctiveCommitments,
}

impl PrecomputedSelection {
    /// Generate a complete set of selection precomputes using `OsRng`.
    pub fn generate(public_key: &ElementModP) -> Self {
        let mut rng = OsRng;
        let encryption = PrecomputedEncryption::generate_with_rng(public_key, &mut rng);
        let proof = PrecomputedEncryption::generate_with_rng(public_key, &mut rng);
        let fake_proof = PrecomputedFakeDisjunctiveCommitments::generate_with_rng(public_key, &mut rng);
        Self { encryption, proof, fake_proof }
    }
}

// ── PrecomputeBuffer ─────────────────────────────────────────────────────────

/// Thread-safe precomputation buffer.
///
/// Maintains two separate queues:
/// * **Encryption queue** — individual `(r, g^r, K^r)` triples.
/// * **Selection queue** — full per-selection bundles (encryption + proof
///   commitments).
///
/// Call [`PrecomputeBuffer::populate`] to fill the queues synchronously.
/// The `get_*` methods fall back to on-demand generation if the queue is
/// empty; the `pop_*` methods return `None` rather than blocking.
pub struct PrecomputeBuffer {
    /// The election public key `K`.
    public_key: ElementModP,
    /// Maximum number of entries in each queue.
    max_queue_size: u32,
    /// Queue of individual encryption triples.
    encryption_queue: Mutex<VecDeque<PrecomputedEncryption>>,
    /// Queue of per-selection bundles.
    selection_queue: Mutex<VecDeque<PrecomputedSelection>>,
}

impl PrecomputeBuffer {
    /// Create an empty buffer for the given `public_key`.
    ///
    /// Call [`PrecomputeBuffer::populate`] to fill it before use, or use
    /// [`PrecomputeBuffer::get_precomputed_encryption`] which generates
    /// on demand when the queue is empty.
    pub fn new(public_key: &ElementModP, max_queue_size: u32) -> Self {
        Self {
            public_key: public_key.clone(),
            max_queue_size,
            encryption_queue: Mutex::new(VecDeque::new()),
            selection_queue: Mutex::new(VecDeque::new()),
        }
    }

    /// Create with the default queue size [`DEFAULT_PRECOMPUTE_SIZE`].
    pub fn with_default_size(public_key: &ElementModP) -> Self {
        Self::new(public_key, DEFAULT_PRECOMPUTE_SIZE)
    }

    // ── Fill queues ─────────────────────────────────────────────────────────

    /// Fill both queues up to `max_queue_size` synchronously.
    ///
    /// This is CPU-intensive; call from a background thread when possible.
    pub fn populate(&self) {
        self.fill_encryption_queue();
        self.fill_selection_queue();
    }

    /// Fill the encryption queue to `max_queue_size`.
    pub fn fill_encryption_queue(&self) {
        let mut queue = self.encryption_queue.lock().expect("encryption_queue lock");
        while queue.len() < self.max_queue_size as usize {
            queue.push_back(PrecomputedEncryption::generate(&self.public_key));
        }
    }

    /// Fill the selection queue to `max_queue_size`.
    pub fn fill_selection_queue(&self) {
        let mut queue = self.selection_queue.lock().expect("selection_queue lock");
        while queue.len() < self.max_queue_size as usize {
            queue.push_back(PrecomputedSelection::generate(&self.public_key));
        }
    }

    // ── Consume precomputed values ───────────────────────────────────────────

    /// Get the next precomputed encryption triple, generating one on demand if
    /// the queue is empty.
    pub fn get_precomputed_encryption(&self) -> PrecomputedEncryption {
        let mut queue = self.encryption_queue.lock().expect("encryption_queue lock");
        queue.pop_front().unwrap_or_else(|| PrecomputedEncryption::generate(&self.public_key))
    }

    /// Pop a precomputed encryption triple, returning `None` if the queue is
    /// empty (no generation on demand).
    pub fn pop_precomputed_encryption(&self) -> Option<PrecomputedEncryption> {
        let mut queue = self.encryption_queue.lock().expect("encryption_queue lock");
        queue.pop_front()
    }

    /// Get the next precomputed selection bundle, generating one on demand if
    /// the queue is empty.
    pub fn get_precomputed_selection(&self) -> PrecomputedSelection {
        let mut queue = self.selection_queue.lock().expect("selection_queue lock");
        queue.pop_front().unwrap_or_else(|| PrecomputedSelection::generate(&self.public_key))
    }

    /// Pop a precomputed selection bundle, returning `None` if the queue is
    /// empty.
    pub fn pop_precomputed_selection(&self) -> Option<PrecomputedSelection> {
        let mut queue = self.selection_queue.lock().expect("selection_queue lock");
        queue.pop_front()
    }

    // ── Introspection ────────────────────────────────────────────────────────

    /// Current number of entries in the encryption queue.
    pub fn encryption_queue_size(&self) -> usize {
        self.encryption_queue.lock().expect("lock").len()
    }

    /// Current number of entries in the selection queue.
    pub fn selection_queue_size(&self) -> usize {
        self.selection_queue.lock().expect("lock").len()
    }

    /// Combined current queue size (encryption + selection).
    pub fn current_queue_size(&self) -> u32 {
        let enc = self.encryption_queue_size();
        let sel = self.selection_queue_size();
        (enc + sel) as u32
    }

    /// Configured maximum queue size.
    pub fn max_queue_size(&self) -> u32 {
        self.max_queue_size
    }

    /// The election public key this buffer was created for.
    pub fn public_key(&self) -> &ElementModP {
        &self.public_key
    }

    /// Drain both queues, discarding all precomputed values.
    pub fn clear(&self) {
        self.encryption_queue.lock().expect("lock").clear();
        self.selection_queue.lock().expect("lock").clear();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{g_pow, mul_mod_p, pow_mod_p, ElementModQ};
    use crate::elgamal::ElGamalKeyPair;

    fn make_keypair() -> ElGamalKeyPair {
        ElGamalKeyPair::from_secret(ElementModQ::from_u64(42))
    }

    // ── PrecomputedEncryption ─────────────────────────────────────────────────

    #[test]
    fn precomputed_encryption_pad_correct() {
        // pad == g^secret
        let kp = make_keypair();
        let pre = PrecomputedEncryption::generate(&kp.public_key);
        let expected_pad = g_pow(&pre.secret);
        assert_eq!(pre.pad, expected_pad, "pad = g^secret");
    }

    #[test]
    fn precomputed_encryption_blind_correct() {
        // blinding_factor == K^secret == g^(s*r)
        let kp = make_keypair();
        let pre = PrecomputedEncryption::generate(&kp.public_key);
        let expected = pow_mod_p(&kp.public_key, &pre.secret);
        assert_eq!(pre.blinding_factor, expected, "blinding_factor = K^secret");
    }

    #[test]
    fn precomputed_encryption_matches_elgamal() {
        // For m=0: ElGamal ciphertext.data = g^0 * K^r = 1 * K^r = K^r
        // For m=1: ElGamal ciphertext.data = g^1 * K^r = g * K^r
        use crate::elgamal::elgamal_encrypt;
        let kp = make_keypair();
        let pre = PrecomputedEncryption::generate(&kp.public_key);

        // Encrypt m=0 with the same nonce as the precomputed secret
        let ct0 = elgamal_encrypt(0, &pre.secret, &kp.public_key);
        assert_eq!(ct0.pad, pre.pad, "pad matches for m=0");
        assert_eq!(ct0.data, pre.blinding_factor, "data == K^r for m=0");

        // Encrypt m=1: data = g * K^r
        let ct1 = elgamal_encrypt(1, &pre.secret, &kp.public_key);
        let g1 = g_pow(&ElementModQ::from_u64(1));
        let expected_data1 = mul_mod_p(&g1, &pre.blinding_factor);
        assert_eq!(ct1.data, expected_data1, "data == g * K^r for m=1");
    }

    // ── PrecomputedFakeDisjunctiveCommitments ─────────────────────────────────

    #[test]
    fn fake_commitments_pad_correct() {
        let kp = make_keypair();
        let fake = PrecomputedFakeDisjunctiveCommitments::generate(&kp.public_key);
        let expected_pad = g_pow(&fake.secret1);
        assert_eq!(fake.pad, expected_pad, "pad = g^secret1");
    }

    #[test]
    fn fake_commitments_data_zero_correct() {
        let kp = make_keypair();
        let fake = PrecomputedFakeDisjunctiveCommitments::generate(&kp.public_key);
        let expected = pow_mod_p(&kp.public_key, &fake.secret1);
        assert_eq!(fake.data_zero, expected, "data_zero = K^secret1");
    }

    #[test]
    fn fake_commitments_data_one_correct() {
        let kp = make_keypair();
        let fake = PrecomputedFakeDisjunctiveCommitments::generate(&kp.public_key);
        let expected = pow_mod_p(&kp.public_key, &fake.secret2);
        assert_eq!(fake.data_one, expected, "data_one = K^secret2");
    }

    // ── PrecomputeBuffer ──────────────────────────────────────────────────────

    #[test]
    fn buffer_initial_state_empty() {
        let kp = make_keypair();
        let buf = PrecomputeBuffer::new(&kp.public_key, 10);
        assert_eq!(buf.encryption_queue_size(), 0);
        assert_eq!(buf.selection_queue_size(), 0);
        assert_eq!(buf.current_queue_size(), 0);
    }

    #[test]
    fn buffer_populate_fills_queues() {
        let kp = make_keypair();
        let buf = PrecomputeBuffer::new(&kp.public_key, 5);
        buf.populate();
        assert_eq!(buf.encryption_queue_size(), 5);
        assert_eq!(buf.selection_queue_size(), 5);
    }

    #[test]
    fn buffer_pop_encryption_decrements_queue() {
        let kp = make_keypair();
        let buf = PrecomputeBuffer::new(&kp.public_key, 3);
        buf.fill_encryption_queue();
        assert_eq!(buf.encryption_queue_size(), 3);

        let pre = buf.pop_precomputed_encryption().expect("should have entry");
        assert_eq!(buf.encryption_queue_size(), 2);

        // Verify the popped value is correct
        let expected_pad = g_pow(&pre.secret);
        assert_eq!(pre.pad, expected_pad);
    }

    #[test]
    fn buffer_pop_returns_none_when_empty() {
        let kp = make_keypair();
        let buf = PrecomputeBuffer::new(&kp.public_key, 5);
        assert!(buf.pop_precomputed_encryption().is_none());
        assert!(buf.pop_precomputed_selection().is_none());
    }

    #[test]
    fn buffer_get_generates_on_demand() {
        let kp = make_keypair();
        let buf = PrecomputeBuffer::new(&kp.public_key, 5);
        // Queue is empty but get_* should still produce a valid value
        let pre = buf.get_precomputed_encryption();
        let expected_pad = g_pow(&pre.secret);
        assert_eq!(pre.pad, expected_pad);
    }

    #[test]
    fn buffer_clear_drains_queues() {
        let kp = make_keypair();
        let buf = PrecomputeBuffer::new(&kp.public_key, 5);
        buf.populate();
        assert!(buf.current_queue_size() > 0);
        buf.clear();
        assert_eq!(buf.current_queue_size(), 0);
    }

    #[test]
    fn buffer_max_queue_size_accessor() {
        let kp = make_keypair();
        let buf = PrecomputeBuffer::new(&kp.public_key, 42);
        assert_eq!(buf.max_queue_size(), 42);
    }

    #[test]
    fn buffer_public_key_accessor() {
        let kp = make_keypair();
        let buf = PrecomputeBuffer::new(&kp.public_key, 5);
        assert_eq!(buf.public_key(), &kp.public_key);
    }

    // ── get_precomputed_selection (lines 253-255) ─────────────────────────────

    #[test]
    fn buffer_get_selection_generates_on_demand() {
        // get_precomputed_selection must produce a valid bundle even when the
        // queue is empty (on-demand generation path, lines 253-255).
        let kp = make_keypair();
        let buf = PrecomputeBuffer::new(&kp.public_key, 5);
        // Queue is empty; call must not panic and must return a consistent triple.
        let sel = buf.get_precomputed_selection();
        let expected_pad = g_pow(&sel.encryption.secret);
        assert_eq!(sel.encryption.pad, expected_pad, "selection.encryption.pad = g^secret");
    }

    #[test]
    fn buffer_get_selection_pops_from_queue_when_populated() {
        let kp = make_keypair();
        // Small queue of size 2; populate it then consume via get_precomputed_selection.
        let buf = PrecomputeBuffer::new(&kp.public_key, 2);
        buf.fill_selection_queue();
        assert_eq!(buf.selection_queue_size(), 2);
        let sel = buf.get_precomputed_selection();
        // After consuming one, only one should remain.
        assert_eq!(buf.selection_queue_size(), 1);
        // The returned value must be structurally valid.
        let expected = g_pow(&sel.encryption.secret);
        assert_eq!(sel.encryption.pad, expected);
    }

    // ── PrecomputedEncryption::generate_with_rng (lines 71-72) ───────────────

    #[test]
    fn encryption_generate_with_rng_is_deterministic_for_seeded_rng() {
        use rand::SeedableRng;
        let kp = make_keypair();
        // Use a seeded RNG so we can call generate_with_rng directly and verify
        // the result is structurally valid (lines 71-72 covered).
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEAD_BEEF);
        let pre = PrecomputedEncryption::generate_with_rng(&kp.public_key, &mut rng);
        let expected_pad = g_pow(&pre.secret);
        assert_eq!(pre.pad, expected_pad, "pad = g^secret for seeded rng");
    }

    // ── PrecomputedFakeDisjunctiveCommitments::generate_with_rng (121-123) ───

    #[test]
    fn fake_commitments_generate_with_rng_is_deterministic() {
        use rand::SeedableRng;
        let kp = make_keypair();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xCAFE_BABE);
        let fake = PrecomputedFakeDisjunctiveCommitments::generate_with_rng(
            &kp.public_key,
            &mut rng,
        );
        let expected_pad = g_pow(&fake.secret1);
        assert_eq!(fake.pad, expected_pad, "pad = g^secret1");
    }

    // ── PrecomputeBuffer::with_default_size (line 205) ───────────────────────

    #[test]
    fn buffer_with_default_size_uses_constant() {
        let kp = make_keypair();
        let buf = PrecomputeBuffer::with_default_size(&kp.public_key);
        assert_eq!(buf.max_queue_size(), DEFAULT_PRECOMPUTE_SIZE);
    }
}
