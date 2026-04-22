//! ElectionGuard Core2 — Rust implementation of the ElectionGuard v2.1 spec.
//!
//! End-to-end verifiable encrypted voting using exponential ElGamal
//! homomorphic encryption over a 4096-bit safe prime group, threshold
//! cryptography, and HMAC-SHA-256 hash chains.
//!
//! # Crate structure
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`error`]       | Error enum and `Result<T>` alias |
//! | [`group`]       | `ElementModP`, `ElementModQ`, arithmetic operations |
//! | [`serialize`]   | Serde helpers for hex-encoded big integers |
//! | [`hmac`]        | HMAC-SHA-256 wrapper |
//! | [`hash`]        | v2.1 HMAC-based hash function and `CryptoHashable` trait |
//! | [`kdf`]         | SP 800-108r1 counter-mode key derivation |
//! | [`nonces`]      | Deterministic nonce sequences and per-selection nonce derivation |
//! | [`elgamal`]     | ElGamal encryption/decryption and hashed ElGamal |
//! | [`proof`]       | Zero-knowledge proof types (Phase 4 stubs) |
//! | [`manifest`]    | Election manifest domain types and `InternalManifest` |
//! | [`election`]    | `CiphertextElectionContext` and parameter hash chain |
//! | [`ballot`]      | Plaintext/ciphertext/submitted ballot types |
//! | [`ballot_code`] | Ballot code and confirmation code computation |

// ── Module declarations ────────────────────────────────────────────────────

/// Error types.
pub mod error;

/// Group elements (`ElementModP`, `ElementModQ`) and all arithmetic operations.
pub mod group;

/// Serde helpers for hex-encoded `U4096` and `U256` big integers.
pub mod serialize;

/// HMAC-SHA-256 primitives.
pub mod hmac;

/// v2.1 HMAC-based hash function, `CryptoHashable` trait, `HashableValue` enum.
pub mod hash;

/// SP 800-108r1 counter-mode KDF using HMAC-SHA-256.
pub mod kdf;

/// Deterministic nonce sequences and v2.1 per-selection nonce derivation.
pub mod nonces;

/// ElGamal encryption, hashed ElGamal, and key pair types.
pub mod elgamal;

/// Zero-knowledge proof types (Phase 4 stubs: ranged, disjunctive, constant, unified-range).
pub mod proof;

/// Election manifest domain types (`Manifest`, `InternalManifest`, contest/selection types).
pub mod manifest;

/// Election context and parameter/base/extended-base hash chain.
pub mod election;

/// Plaintext, ciphertext, and submitted ballot types.
pub mod ballot;

/// Ballot code, confirmation code, and chaining field computation.
pub mod ballot_code;

/// Guardian key ceremony: Schnorr proofs, polynomial key generation, and share exchange.
pub mod guardian;

/// Ballot encryption: selections, contests, and full ballots (Phase 7).
pub mod encrypt;

/// Baby-step / giant-step discrete logarithm solver for ElGamal decryption.
pub mod discrete_log;

/// Precomputed ElGamal encryption triples and per-selection bundles.
pub mod precompute;

/// Threshold decryption: partial shares, Chaum-Pedersen proofs, Lagrange interpolation.
pub mod decryption;

// ── Convenience re-exports ─────────────────────────────────────────────────

pub use error::{Error, Result};
pub use group::{
    ElementModP, ElementModQ,
    // Arithmetic — P
    mul_mod_p, pow_mod_p, div_mod_p, inv_mod_p, g_pow,
    // Arithmetic — Q
    add_mod_q, sub_mod_q, mul_mod_q, pow_mod_q, div_mod_q, inv_mod_q,
    a_plus_bc_mod_q, a_minus_bc_mod_q, negate_mod_q,
};
pub use hash::{CryptoHashable, HashableValue, hash_elems_v21, hash_elems_v21_q, hash_elems_v21_raw};
pub use hmac::{hmac_sha256, hmac_sha256_verify};
pub use kdf::{kdf_hmac_sha256, kdf_key};
pub use nonces::{
    Nonces,
    compute_selection_encryption_id,
    derive_selection_nonce,
    derive_contest_data_nonce,
};
pub use elgamal::{
    ElGamalCiphertext, HashedElGamalCiphertext, ElGamalKeyPair,
    elgamal_encrypt, elgamal_add, elgamal_accumulate,
};
pub use manifest::{
    Manifest, InternalManifest,
    ContestDescription, ContestDescriptionWithPlaceholders,
    SelectionDescription, BallotStyle, GeopoliticalUnit, Party, Candidate,
    ElectionType, ReportingUnitType, VoteVariationType,
    generate_placeholder_selection,
};
pub use election::{
    CiphertextElectionContext,
    compute_parameter_hash, compute_base_hash, compute_extended_base_hash,
};
pub use ballot::{
    BallotBoxState,
    PlaintextBallot, PlaintextBallotContest, PlaintextBallotSelection,
    CiphertextBallot, CiphertextBallotContest, CiphertextBallotSelection,
    SubmittedBallot,
};
pub use ballot_code::{
    get_hash_for_device, get_ballot_code,
    compute_contest_hash, compute_device_info_hash, compute_confirmation_code,
    build_no_chaining_field, build_simple_chain_init_field, build_simple_chain_field,
    compute_chain_init_hash, close_chain,
};
pub use discrete_log::DiscreteLogTable;
pub use precompute::{
    PrecomputeBuffer, PrecomputedEncryption, PrecomputedFakeDisjunctiveCommitments,
    PrecomputedSelection,
};
pub use decryption::{
    DecryptionProof, PartialDecryption, TallyDecryptionShare,
    compute_lagrange_coefficient, combine_partial_decryptions,
    compute_decryption_share, verify_decryption_proof,
    decrypt_tally_with_shares, compute_compensated_decryption_share,
};
