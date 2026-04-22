# ElectionGuard Core2 — Rust Port Architecture Specification

> v2.1 spec · Single crate · Clean-slate implementation

---

## 1. Overview

This specification defines the complete architecture for porting the ElectionGuard Core2 C++17 SDK
to idiomatic Rust. The SDK implements end-to-end verifiable encrypted voting using:

- **Exponential ElGamal** homomorphic encryption over a 4096-bit prime group
- **Threshold cryptography** with Shamir secret sharing for key ceremony
- **HMAC-SHA-256** hash chains with v2.1 domain-separated hashing
- **Zero-knowledge proofs** (Chaum-Pedersen disjunctive, ranged, constant, unified range)
- **Confirmation code chaining** for ballot integrity

### Design Principles

1. **Constant-time arithmetic** — all secret-dependent operations use `crypto-bigint`
2. **Type safety** — `ElementModP` and `ElementModQ` are distinct types preventing misuse
3. **Zeroize on drop** — all secret material is zeroized when dropped
4. **No global singletons** — unlike C++, use explicit context passing (no `DiscreteLog::getInstance`)
5. **Error propagation** — `Result<T, Error>` everywhere, no panics in library code
6. **Serde-first serialization** — JSON via `serde` derives, no BSON/MsgPack initially

---

## 2. Dependency Choices

### Cargo.toml

```toml
[package]
name = "electionguard-core2"
version = "0.1.0"
edition = "2024"
rust-version = "1.85"
license = "MIT"
description = "ElectionGuard Core2 cryptographic voting SDK (v2.1 spec)"

[dependencies]
crypto-bigint = { version = "0.6", features = ["rand_core"] }
hmac = "0.12"
sha2 = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
rand = "0.8"
rand_core = "0.6"
zeroize = { version = "1", features = ["derive", "zeroize_derive"] }
thiserror = "2"
hex = "0.4"
subtle = "2"

[dev-dependencies]
proptest = "1"
criterion = { version = "0.5", features = ["html_reports"] }
serde_json = "1"
rand = "0.8"

[[bench]]
name = "group_ops"
harness = false

[[bench]]
name = "encrypt"
harness = false
```

### Rationale

| Crate | Why | Alternative Rejected |
|-------|-----|---------------------|
| `crypto-bigint` 0.6 | Fixed-size `U256`/`U4096` with constant-time ops. Matches our fixed group sizes exactly. Has `DynResidue` for modular arithmetic with `pow`, `invert`, `mul`. | `num-bigint` — not constant-time, timing side channels would leak secret keys |
| `hmac` + `sha2` | RustCrypto standard HMAC-SHA-256. Matches C++ HACL* semantics. | `ring` — heavier, less composable |
| `subtle` | Constant-time comparison for `ElementModQ` equality checks | Manual CT comparisons — error-prone |
| `zeroize` | Derive macro for auto-zeroize on Drop for secret material | Manual `Drop` impls — easy to forget fields |
| `thiserror` | Derive macro for clean error enums with zero boilerplate | `anyhow` — too opaque for a library crate |
| `serde` + `serde_json` | Standard Rust serialization. JSON matches C++ `toJson`/`fromJson` | `simd-json` — premature optimization |
| `rand` + `rand_core` | Standard randomness. `OsRng` for production, seedable for tests | `getrandom` alone — insufficient for the API |
| `hex` | Hex encoding for `ElementModP`/`ElementModQ` display | Manual hex formatting — why? |

---

## 3. Module Tree

```
rust/
├── Cargo.toml
├── ARCHITECTURE.md          ← this file
├── src/
│   ├── lib.rs               ← crate root, re-exports
│   ├── error.rs             ← Error enum
│   ├── group/
│   │   ├── mod.rs           ← ElementModP, ElementModQ, arithmetic ops
│   │   └── constants.rs     ← P, Q, G, R, domain separation bytes, constants
│   ├── hash.rs              ← CryptoHashable trait, hash_elems_v21, hash_elems_v21_q
│   ├── hmac.rs              ← HMAC::compute (thin wrapper)
│   ├── kdf.rs               ← SP 800-108r1 counter-mode KDF
│   ├── nonces.rs            ← Nonces generator, nonce derivation functions
│   ├── elgamal.rs           ← ElGamalKeyPair, ElGamalCiphertext, HashedElGamalCiphertext
│   ├── proof/
│   │   ├── mod.rs           ← ChaumPedersenProof (base), exports
│   │   ├── disjunctive.rs   ← DisjunctiveChaumPedersenProof
│   │   ├── constant.rs      ← ConstantChaumPedersenProof
│   │   ├── ranged.rs        ← RangedChaumPedersenProof
│   │   └── unified_range.rs ← UnifiedRangeProof
│   ├── manifest.rs          ← Manifest, InternalManifest, SelectionDescription, etc.
│   ├── election.rs          ← CiphertextElectionContext, parameter hash chain
│   ├── ballot.rs            ← Plaintext/Ciphertext/SubmittedBallot
│   ├── ballot_code.rs       ← BallotCode: contest hash, confirmation code, chaining
│   ├── guardian.rs           ← GuardianKeySet, SchnorrProof, shares, polynomial
│   ├── encrypt.rs           ← EncryptionDevice, EncryptionMediator, encryptBallot
│   ├── decryption.rs        ← DecryptionProof, Lagrange interpolation
│   ├── discrete_log.rs      ← DiscreteLogTable (baby-step/giant-step)
│   ├── precompute.rs        ← PrecomputedEncryption, PrecomputeBuffer
│   └── serialize.rs         ← Serde helpers (hex encoding for big integers)
├── tests/
│   ├── group_tests.rs
│   ├── hash_tests.rs
│   ├── elgamal_tests.rs
│   ├── proof_tests.rs
│   ├── election_tests.rs
│   ├── ballot_tests.rs
│   ├── guardian_tests.rs
│   ├── encrypt_tests.rs
│   └── e2e_tests.rs         ← full election lifecycle
└── benches/
    ├── group_ops.rs
    └── encrypt.rs
```

---

## 4. Module Dependency Graph

```
Layer 0 (Foundation):
  error
  group/constants

Layer 1 (Primitives):
  group/mod         → error, group/constants
  serialize         → group/mod

Layer 2 (Cryptographic Utilities):
  hmac              → (external only: hmac, sha2)
  hash              → group/mod, hmac, error
  kdf               → hmac, error
  nonces            → group/mod, hash, error

Layer 3 (Encryption):
  elgamal           → group/mod, hash, hmac, error

Layer 4 (Proofs):
  proof/mod         → group/mod, hash, elgamal, error
  proof/disjunctive → proof/mod, group/mod, hash, elgamal
  proof/constant    → proof/mod, group/mod, hash, elgamal
  proof/ranged      → proof/mod, proof/disjunctive, group/mod, hash, elgamal
  proof/unified     → proof/mod, group/mod, hash, elgamal

Layer 5 (Election Domain):
  manifest          → group/mod, hash, error, serialize
  election          → group/mod, hash, manifest, error, serialize

Layer 6 (Ballot & Guardian):
  ballot_code       → group/mod, hash, elgamal, error
  ballot            → group/mod, hash, elgamal, proof, election, ballot_code, serialize, error
  guardian          → group/mod, hash, elgamal, election, error, serialize

Layer 7 (Operations):
  precompute        → group/mod, elgamal, error
  encrypt           → group/mod, hash, elgamal, proof, ballot, election, manifest,
                      nonces, ballot_code, precompute, error
  decryption        → group/mod, hash, elgamal, election, error
  discrete_log      → group/mod, error
```

---

## 5. Type Definitions

### 5.1 error.rs

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("value out of range: {0}")]
    OutOfRange(String),

    #[error("invalid proof: {0}")]
    InvalidProof(String),

    #[error("invalid election parameters: {0}")]
    InvalidElection(String),

    #[error("invalid ballot: {0}")]
    InvalidBallot(String),

    #[error("invalid manifest: {0}")]
    InvalidManifest(String),

    #[error("invalid guardian: {0}")]
    InvalidGuardian(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("arithmetic error: {0}")]
    Arithmetic(String),

    #[error("discrete log not found for element (max={0})")]
    DiscreteLogNotFound(u64),
}

pub type Result<T> = std::result::Result<T, Error>;
```

### 5.2 group/constants.rs

```rust
use crypto_bigint::{U256, U4096};

/// Number of u64 limbs in P (4096 / 64 = 64)
pub const MAX_P_LEN: usize = 64;
/// Number of u64 limbs in Q (256 / 64 = 4)
pub const MAX_Q_LEN: usize = 4;
/// Byte size of P
pub const MAX_P_SIZE: usize = 512;
/// Byte size of Q
pub const MAX_Q_SIZE: usize = 32;

/// Default max size for discrete log baby-step/giant-step table
pub const DLOG_MAX_SIZE: u64 = 5_000_000;
/// Default precompute buffer queue size
pub const DEFAULT_PRECOMPUTE_SIZE: u32 = 5_000;

/// The large prime P (4096-bit).
/// Q = 2^256 - 189, P = 2*R*Q + 1 (standard v2.1 primes)
pub const P_VALUE: U4096 = /* 4096-bit constant from C++ P_ARRAY_REVERSE, big-endian U4096 */;

/// The small prime Q = 2^256 - 189
pub const Q_VALUE: U256 = U256::wrapping_sub(
    &U256::MAX.wrapping_add(&U256::ONE),  // 2^256
    &U256::from_u64(189),
);
// NOTE: implementer should verify this produces the correct constant.
// The actual hex: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43

/// Generator G of the subgroup of order Q in Z*_P
pub const G_VALUE: U4096 = /* from G_ARRAY_REVERSE */;

/// Cofactor R = (P - 1) / (2 * Q)
pub const R_VALUE: U4096 = /* from R_ARRAY_REVERSE */;

// ── v2.1 domain separation bytes ───────────────────────────────────
pub const EG_DS_VERSION_LABEL: &[u8] = b"v2.1";
pub const EG_DS_PARAMETER_HASH: u8 = 0x00;
pub const EG_DS_ELECTION_BASE_HASH: u8 = 0x01;
pub const EG_DS_EXTENDED_BASE_HASH: u8 = 0x02;
pub const EG_DS_KEY_GENERATION_NIZK: u8 = 0x10;
pub const EG_DS_SHARE_ENC_KEY: u8 = 0x11;
pub const EG_DS_SHARE_ENC_PROOF: u8 = 0x12;
pub const EG_DS_GUARDIAN_RECORD_HASH: u8 = 0x14;
pub const EG_DS_SELECTION_ENC_ID: u8 = 0x20;
pub const EG_DS_ENCRYPTION_NONCE: u8 = 0x21;
pub const EG_DS_CONTEST_DATA_NONCE: u8 = 0x25;
pub const EG_DS_CONTEST_DATA_ENC_KEY: u8 = 0x26;
pub const EG_DS_CONTEST_DATA_ENC_PROOF: u8 = 0x27;
pub const EG_DS_CONTEST_HASH: u8 = 0x28;
pub const EG_DS_CONFIRMATION_CODE: u8 = 0x29;
pub const EG_DS_DEVICE_INFO_HASH: u8 = 0x2A;
pub const EG_DS_BALLOT_NONCE_ENC_KEY: u8 = 0x2B;
pub const EG_DS_BALLOT_NONCE_ENC_PROOF: u8 = 0x2C;
pub const EG_DS_RANGE_PROOF: u8 = 0x2D;
pub const EG_DS_TALLY_DECRYPT_COMMIT: u8 = 0x30;
pub const EG_DS_TALLY_DECRYPT_PROOF: u8 = 0x31;
pub const EG_DS_CONTEST_DECRYPT_COMMIT: u8 = 0x32;
pub const EG_DS_CONTEST_DECRYPT_PROOF: u8 = 0x33;
pub const EG_DS_CHAIN_CLOSING: u8 = 0x34;
```

> **Implementer note**: The actual P, G, R hex values must be transcribed from
> `include/electionguard/constants.h` (the `*_ARRAY_REVERSE` arrays). Each array
> is 64 × `uint64_t` in little-endian limb order. Convert to big-endian bytes
> for `U4096::from_be_hex(...)`.

### 5.3 group/mod.rs — ElementModP and ElementModQ

```rust
use crypto_bigint::{U256, U4096, NonZero, Encoding, CheckedSub};
use crypto_bigint::modular::{DynResidue, DynResidueParams};
use serde::{Serialize, Deserialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
use std::sync::LazyLock;
use crate::error::{Error, Result};
use crate::group::constants::*;

/// Precomputed DynResidueParams for mod P (4096-bit)
static P_PARAMS: LazyLock<DynResidueParams<{ U4096::LIMBS }>> =
    LazyLock::new(|| DynResidueParams::new(&NonZero::new(P_VALUE).unwrap()));

/// Precomputed DynResidueParams for mod Q (256-bit)
static Q_PARAMS: LazyLock<DynResidueParams<{ U256::LIMBS }>> =
    LazyLock::new(|| DynResidueParams::new(&NonZero::new(Q_VALUE).unwrap()));

// ── ElementModP ──────────────────────────────────────────────────────

/// An element in [0, P) — 4096-bit modular integer.
/// Used for public keys, ciphertext components, generators.
#[derive(Clone, Serialize, Deserialize)]
pub struct ElementModP {
    /// Internal value as U4096 in [0, P). Serialized as 512-byte big-endian hex.
    #[serde(with = "crate::serialize::u4096_hex")]
    value: U4096,
}

impl ElementModP {
    /// Create from raw U4096 value. Returns Err if value >= P.
    pub fn new(value: U4096) -> Result<Self> { .. }

    /// Create from raw U4096 with automatic mod-P reduction.
    pub fn new_unchecked(value: U4096) -> Self { .. }

    /// Create from big-endian bytes (512 bytes).
    pub fn from_bytes_be(bytes: &[u8; MAX_P_SIZE]) -> Result<Self> { .. }

    /// Export as big-endian bytes (512 bytes).
    pub fn to_bytes_be(&self) -> [u8; MAX_P_SIZE] { .. }

    /// Export as lowercase hex string (1024 chars).
    pub fn to_hex(&self) -> String { .. }

    /// Parse from hex string.
    pub fn from_hex(hex: &str) -> Result<Self> { .. }

    /// Get the raw U4096 value.
    pub fn value(&self) -> &U4096 { .. }

    /// Returns true if this element is the identity (1 mod P).
    pub fn is_one(&self) -> bool { .. }

    /// Returns true if this element is zero.
    pub fn is_zero(&self) -> bool { .. }

    // ── Well-known constants (return references to static values) ──

    pub fn zero() -> &'static Self { .. }  // 0
    pub fn one() -> &'static Self { .. }   // 1
    pub fn two() -> &'static Self { .. }   // 2
    pub fn p() -> &'static Self { .. }     // P (the prime itself, for reference)
    pub fn g() -> &'static Self { .. }     // Generator G
    pub fn r() -> &'static Self { .. }     // Cofactor R
}

// ── Arithmetic on ElementModP ──

/// (a * b) mod P — constant-time
pub fn mul_mod_p(a: &ElementModP, b: &ElementModP) -> ElementModP { .. }

/// (base ^ exponent) mod P — constant-time.
/// Exponent is ElementModQ (256-bit).
pub fn pow_mod_p(base: &ElementModP, exponent: &ElementModQ) -> ElementModP { .. }

/// (a * b^-1) mod P — constant-time. Err if b == 0.
pub fn div_mod_p(a: &ElementModP, b: &ElementModP) -> Result<ElementModP> { .. }

/// Multiplicative inverse mod P. Err if a == 0.
pub fn inv_mod_p(a: &ElementModP) -> Result<ElementModP> { .. }

/// g^exponent mod P — convenience for generator exponentiation.
pub fn g_pow(exponent: &ElementModQ) -> ElementModP { .. }

// ── ElementModQ ──────────────────────────────────────────────────────

/// An element in [0, Q) — 256-bit modular integer.
/// Used for secret keys, nonces, hash outputs, exponents.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct ElementModQ {
    #[serde(with = "crate::serialize::u256_hex")]
    value: U256,
}

impl ElementModQ {
    /// Create from raw U256 value. Returns Err if value >= Q.
    pub fn new(value: U256) -> Result<Self> { .. }

    /// Create from raw U256 with automatic mod-Q reduction.
    pub fn new_reduced(value: U256) -> Self { .. }

    /// Create from u64.
    pub fn from_u64(val: u64) -> Self { .. }

    /// Create from big-endian bytes (32 bytes).
    pub fn from_bytes_be(bytes: &[u8; MAX_Q_SIZE]) -> Result<Self> { .. }

    /// Export as big-endian bytes (32 bytes).
    pub fn to_bytes_be(&self) -> [u8; MAX_Q_SIZE] { .. }

    /// Export as lowercase hex string (64 chars).
    pub fn to_hex(&self) -> String { .. }

    /// Parse from hex string.
    pub fn from_hex(hex: &str) -> Result<Self> { .. }

    /// Get the raw U256 value.
    pub fn value(&self) -> &U256 { .. }

    /// Generate a random element in [1, Q).
    pub fn random<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self { .. }

    /// Returns true if this is zero.
    pub fn is_zero(&self) -> bool { .. }

    // ── Constants ──
    pub fn zero() -> &'static Self { .. }
    pub fn one() -> &'static Self { .. }
    pub fn two() -> &'static Self { .. }
}

// ── Arithmetic on ElementModQ ──

/// (a + b) mod Q
pub fn add_mod_q(a: &ElementModQ, b: &ElementModQ) -> ElementModQ { .. }

/// (a - b) mod Q  (wraps if a < b)
pub fn sub_mod_q(a: &ElementModQ, b: &ElementModQ) -> ElementModQ { .. }

/// (a * b) mod Q
pub fn mul_mod_q(a: &ElementModQ, b: &ElementModQ) -> ElementModQ { .. }

/// (base ^ exponent) mod Q
pub fn pow_mod_q(base: &ElementModQ, exponent: &ElementModQ) -> ElementModQ { .. }

/// (a * b^-1) mod Q. Err if b == 0.
pub fn div_mod_q(a: &ElementModQ, b: &ElementModQ) -> Result<ElementModQ> { .. }

/// Multiplicative inverse mod Q. Err if a == 0.
pub fn inv_mod_q(a: &ElementModQ) -> Result<ElementModQ> { .. }

/// (a + b*c) mod Q — fused multiply-add (common in proofs)
pub fn a_plus_bc_mod_q(
    a: &ElementModQ,
    b: &ElementModQ,
    c: &ElementModQ,
) -> ElementModQ { .. }

/// (a - b*c) mod Q — fused multiply-subtract
pub fn a_minus_bc_mod_q(
    a: &ElementModQ,
    b: &ElementModQ,
    c: &ElementModQ,
) -> ElementModQ { .. }

/// Negate: (Q - a) mod Q
pub fn negate_mod_q(a: &ElementModQ) -> ElementModQ { .. }

// ── PartialEq / Eq ──
// Both types implement PartialEq using constant-time comparison (subtle::ConstantTimeEq).
// ElementModP: Eq + PartialEq
// ElementModQ: Eq + PartialEq
// Both implement: Debug (shows hex), Display (shows hex), Hash (for HashMap keys)
```

### 5.4 hash.rs

```rust
use crate::group::{ElementModP, ElementModQ};
use crate::error::Result;

/// Trait for types that can produce a cryptographic hash.
/// Rust equivalent of C++ CryptoHashable.
pub trait CryptoHashable {
    fn crypto_hash(&self) -> Result<ElementModQ>;
}

/// A value that can be serialized into the v2.1 HMAC hash function.
/// Covers: ElementModP (→512B BE), ElementModQ (→32B BE), u64 (→4B BE),
/// String (→UTF-8 bytes), &[u8] (→raw bytes), Vec<CryptoHashableType>.
pub enum HashableValue<'a> {
    ModP(&'a ElementModP),
    ModQ(&'a ElementModQ),
    U64(u64),
    Str(&'a str),
    Bytes(&'a [u8]),
    Null,
    Seq(Vec<HashableValue<'a>>),
}

// Convenience From impls for ergonomic hash_elems_v21 calls:
impl<'a> From<&'a ElementModP> for HashableValue<'a> { .. }
impl<'a> From<&'a ElementModQ> for HashableValue<'a> { .. }
impl<'a> From<u64> for HashableValue<'a> { .. }
impl<'a> From<&'a str> for HashableValue<'a> { .. }
impl<'a> From<&'a [u8]> for HashableValue<'a> { .. }

/// v2.1 HMAC-based hash function: H(key; domainSeparator, args...)
///
/// Process:
/// 1. Serialize each arg to big-endian bytes per v2.1 spec:
///    - ElementModP → 512 bytes BE
///    - ElementModQ → 32 bytes BE
///    - u64 → 4 bytes BE (truncated to u32)
///    - String → UTF-8 bytes prefixed with 4-byte BE length
///    - Bytes → raw bytes prefixed with 4-byte BE length
///    - Null → 0x00000000 (4 zero bytes)
/// 2. Concatenate: [domainSeparator_byte] || serialized_arg_0 || ... || serialized_arg_n
/// 3. HMAC-SHA-256(key=key_bytes_32, message=concatenation)
/// 4. Interpret output as ElementModQ (reduce mod Q)
pub fn hash_elems_v21(
    key: &ElementModQ,
    domain_separator: u8,
    args: &[HashableValue<'_>],
) -> Result<ElementModQ> { .. }

/// v2.1 hash that also reduces mod Q (for challenge computation).
/// Identical to hash_elems_v21 but ensures result is in [0, Q).
/// (In practice hash_elems_v21 already returns mod Q, so this is
/// an alias for clarity matching the C++ API.)
pub fn hash_elems_v21_q(
    key: &ElementModQ,
    domain_separator: u8,
    args: &[HashableValue<'_>],
) -> Result<ElementModQ> { .. }

/// Overload accepting raw 32-byte key (for parameter hash with zero key).
pub fn hash_elems_v21_raw(
    key: &[u8; 32],
    domain_separator: u8,
    args: &[HashableValue<'_>],
) -> Result<ElementModQ> { .. }
```

### 5.5 hmac.rs

```rust
/// HMAC-SHA-256 computation.
///
/// When `length > 0`, uses SP 800-108r1 counter mode framing:
/// message = counter(4B LE) || data || length(4B LE)
pub fn hmac_compute(
    key: &[u8],
    message: &[u8],
    length: u32,
    start: u32,
) -> Vec<u8> { .. }

/// Simple HMAC-SHA-256: HMAC(key, message) with no framing.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] { .. }
```

### 5.6 kdf.rs

```rust
use crate::error::Result;

/// SP 800-108r1 counter-mode KDF using HMAC-SHA-256.
///
/// Derives `length` bytes of key material from `key` and `label`/`context`.
/// Uses counter mode with 32-bit counter prepended and 32-bit length appended.
pub fn kdf(
    key: &[u8],
    label: &[u8],
    context: &[u8],
    length: u32,
) -> Result<Vec<u8>> { .. }
```

### 5.7 nonces.rs

```rust
use crate::group::ElementModQ;
use crate::error::Result;

/// Deterministic nonce sequence generator.
/// Given a seed (and optional header), produces an indexed sequence of nonces
/// by hashing: nonce[i] = H(seed; header || i).
pub struct Nonces {
    seed: ElementModQ,
    header: Option<Vec<u8>>,
    counter: u64,
}

impl Nonces {
    pub fn new(seed: &ElementModQ) -> Self { .. }
    pub fn with_header(seed: &ElementModQ, header: &[u8]) -> Self { .. }

    /// Get nonce at index `item`.
    pub fn get(&self, item: u64) -> Result<ElementModQ> { .. }

    /// Get nonce at index `item` with additional string header.
    pub fn get_with_header(&self, item: u64, header: &str) -> Result<ElementModQ> { .. }

    /// Get a range of nonces [start, start+count).
    pub fn get_range(&self, start: u64, count: u64) -> Result<Vec<ElementModQ>> { .. }

    /// Get and advance the internal counter.
    pub fn next(&mut self) -> Result<ElementModQ> { .. }
}

/// v2.1: H_I = H(H_E; 0x20, id_B) — selection encryption identifier.
pub fn compute_selection_encryption_id(
    extended_hash: &ElementModQ,
    ballot_id: &ElementModQ,
) -> Result<ElementModQ> { .. }

/// v2.1: xi_{i,j} = H_q(H_I; 0x21, i, j, xi_B) — per-selection nonce.
pub fn derive_selection_nonce(
    selection_enc_id: &ElementModQ,
    contest_index: u64,
    selection_index: u64,
    ballot_nonce: &ElementModQ,
) -> Result<ElementModQ> { .. }

/// v2.1: xi = H_q(H_I; 0x25, ind_c, xi_B) — contest data nonce.
pub fn derive_contest_data_nonce(
    selection_enc_id: &ElementModQ,
    contest_index: u64,
    ballot_nonce: &ElementModQ,
) -> Result<ElementModQ> { .. }
```

### 5.8 elgamal.rs

```rust
use crate::group::{ElementModP, ElementModQ};
use crate::error::Result;
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

/// ElGamal public/secret key pair.
#[derive(Clone)]
pub struct ElGamalKeyPair {
    /// Secret key s ∈ [1, Q)
    secret_key: ElementModQ,
    /// Public key K = g^s mod P
    public_key: ElementModP,
}

impl ElGamalKeyPair {
    pub fn generate<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self { .. }
    pub fn from_secret(secret: &ElementModQ) -> Self { .. }
    pub fn secret_key(&self) -> &ElementModQ { .. }
    pub fn public_key(&self) -> &ElementModP { .. }
}

impl Drop for ElGamalKeyPair {
    fn drop(&mut self) { self.secret_key.zeroize(); }
}

/// Standard ElGamal ciphertext: (pad = g^r, data = K^r * g^m).
/// Homomorphic: multiply pads and datas to add plaintexts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalCiphertext {
    /// pad = g^r mod P (also called alpha, or A)
    pub pad: ElementModP,
    /// data = g^m * K^r mod P (also called beta, or B)
    pub data: ElementModP,
}

impl ElGamalCiphertext {
    pub fn new(pad: ElementModP, data: ElementModP) -> Self { .. }
}

/// Hashed ElGamal ciphertext for encrypting arbitrary data (contest data, nonces).
/// Scheme: pad = g^r, then derive symmetric key from K^r, encrypt with AES-CTR or
/// XOR, and authenticate with HMAC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashedElGamalCiphertext {
    /// pad = g^r mod P (C0)
    pub pad: ElementModP,
    /// Encrypted data bytes (C1)
    pub data: Vec<u8>,
    /// HMAC-SHA-256 authentication tag (C2)
    pub mac: Vec<u8>,
}

/// Encrypt a vote value m ∈ {0, 1, ...} using ElGamal.
/// Returns (g^r, g^m · K^r) with random nonce r.
pub fn elgamal_encrypt(
    plaintext: u64,
    nonce: &ElementModQ,
    public_key: &ElementModP,
) -> ElGamalCiphertext { .. }

/// Homomorphic addition: element-wise multiplication of ciphertexts.
/// encrypt(a) ⊕ encrypt(b) = encrypt(a + b)
pub fn elgamal_add(
    a: &ElGamalCiphertext,
    b: &ElGamalCiphertext,
) -> ElGamalCiphertext { .. }

/// Homomorphic accumulation of multiple ciphertexts.
pub fn elgamal_accumulate(
    ciphertexts: &[&ElGamalCiphertext],
) -> ElGamalCiphertext { .. }

/// Hashed ElGamal encryption for arbitrary-length data.
/// Uses the data encryption key K̂ (k_hat) for contest data.
pub fn hashed_elgamal_encrypt(
    message: &[u8],
    nonce: &ElementModQ,
    public_key: &ElementModP,
    selection_enc_id: &ElementModQ,
    contest_index: u64,
    should_verify: bool,
) -> Result<HashedElGamalCiphertext> { .. }

/// Hashed ElGamal decryption.
pub fn hashed_elgamal_decrypt(
    ciphertext: &HashedElGamalCiphertext,
    secret_key: &ElementModQ,
    selection_enc_id: &ElementModQ,
    contest_index: u64,
) -> Result<Vec<u8>> { .. }

/// Encrypt the ballot nonce for the voter (v2.1 signed hashed ElGamal with K̂).
pub fn encrypt_ballot_nonce(
    ballot_nonce: &ElementModQ,
    nonce: &ElementModQ,
    data_public_key: &ElementModP,
    selection_enc_id: &ElementModQ,
) -> Result<HashedElGamalCiphertext> { .. }

/// Verify encrypted ballot nonce.
pub fn verify_ballot_nonce(
    ciphertext: &HashedElGamalCiphertext,
    data_public_key: &ElementModP,
    selection_enc_id: &ElementModQ,
) -> Result<bool> { .. }
```

### 5.9 proof/mod.rs — Base proof type

```rust
use crate::group::{ElementModP, ElementModQ};
use serde::{Serialize, Deserialize};

/// Base Chaum-Pedersen proof: (commitment, challenge, response).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaumPedersenProof {
    /// Commitment (a = g^w mod P)
    pub pad: ElementModP,
    /// Commitment (b = K^w mod P)
    pub data: ElementModP,
    /// Challenge c
    pub challenge: ElementModQ,
    /// Response r = w - c*s mod Q
    pub response: ElementModQ,
}

pub mod disjunctive;
pub mod constant;
pub mod ranged;
pub mod unified_range;
```

### 5.10 proof/disjunctive.rs

```rust
use crate::group::{ElementModP, ElementModQ};
use crate::elgamal::ElGamalCiphertext;
use crate::proof::ChaumPedersenProof;
use crate::precompute::{PrecomputedEncryption, PrecomputedFakeDisjunctiveCommitments};
use crate::error::Result;
use serde::{Serialize, Deserialize};

/// Proves a ciphertext encrypts 0 or 1 (disjunctive proof).
/// Contains two sub-proofs: one real, one simulated.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisjunctiveChaumPedersenProof {
    pub proof_zero: ChaumPedersenProof,
    pub proof_one: ChaumPedersenProof,
    pub challenge: ElementModQ,
}

impl DisjunctiveChaumPedersenProof {
    /// Generate a proof that `ciphertext` encrypts `plaintext` ∈ {0, 1}.
    pub fn make(
        ciphertext: &ElGamalCiphertext,
        plaintext: u64,
        nonce: &ElementModQ,
        public_key: &ElementModP,
        seed: &ElementModQ,
        selection_enc_id: &ElementModQ,
    ) -> Result<Self> { .. }

    /// Generate using precomputed values.
    pub fn make_with_precompute(
        ciphertext: &ElGamalCiphertext,
        plaintext: u64,
        nonce: &ElementModQ,
        public_key: &ElementModP,
        selection_enc_id: &ElementModQ,
        precomputed_enc: &PrecomputedEncryption,
        precomputed_fake: &PrecomputedFakeDisjunctiveCommitments,
    ) -> Result<Self> { .. }

    /// Verify the proof against the ciphertext and public key.
    pub fn verify(
        &self,
        ciphertext: &ElGamalCiphertext,
        public_key: &ElementModP,
        extended_hash: &ElementModQ,
    ) -> bool { .. }
}
```

### 5.11 proof/ranged.rs

```rust
use crate::group::{ElementModP, ElementModQ};
use crate::elgamal::ElGamalCiphertext;
use crate::proof::ChaumPedersenProof;
use crate::error::Result;
use serde::{Serialize, Deserialize};

/// Ranged Chaum-Pedersen proof: proves a ciphertext encrypts a value in [0, limit].
/// Composed of (limit + 1) individual proofs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangedChaumPedersenProof {
    pub range_limit: u64,
    pub individual_proofs: Vec<ChaumPedersenProof>,
    pub challenge: ElementModQ,
}

impl RangedChaumPedersenProof {
    /// Generate a ranged proof.
    pub fn make(
        ciphertext: &ElGamalCiphertext,
        plaintext: u64,
        nonce: &ElementModQ,
        public_key: &ElementModP,
        seed: &ElementModQ,
        range_limit: u64,
        selection_enc_id: &ElementModQ,
    ) -> Result<Self> { .. }

    /// Verify the ranged proof.
    pub fn verify(
        &self,
        ciphertext: &ElGamalCiphertext,
        public_key: &ElementModP,
        extended_hash: &ElementModQ,
    ) -> bool { .. }
}
```

### 5.12 proof/constant.rs

```rust
use crate::group::{ElementModP, ElementModQ};
use crate::elgamal::ElGamalCiphertext;
use crate::proof::ChaumPedersenProof;
use crate::error::Result;
use serde::{Serialize, Deserialize};

/// Constant Chaum-Pedersen proof: proves a ciphertext accumulation
/// encrypts exactly `constant` (the contest vote limit).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstantChaumPedersenProof {
    pub proof: ChaumPedersenProof,
    pub constant: u64,
}

impl ConstantChaumPedersenProof {
    pub fn make(
        ciphertext: &ElGamalCiphertext,
        constant: u64,
        nonce: &ElementModQ,
        public_key: &ElementModP,
        seed: &ElementModQ,
        extended_hash: &ElementModQ,
    ) -> Result<Self> { .. }

    pub fn verify(
        &self,
        ciphertext: &ElGamalCiphertext,
        public_key: &ElementModP,
        extended_hash: &ElementModQ,
    ) -> bool { .. }
}
```

### 5.13 proof/unified_range.rs

```rust
use crate::group::{ElementModP, ElementModQ};
use crate::elgamal::ElGamalCiphertext;
use crate::error::Result;
use serde::{Serialize, Deserialize};

/// v2.1 Unified Range Proof — proves encryptions are in [0, 2^b - 1].
/// Used for both selection proofs and contest total proofs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnifiedRangeProof {
    pub commitments: Vec<ElementModP>,
    pub challenge: ElementModQ,
    pub responses: Vec<ElementModQ>,
}

impl UnifiedRangeProof {
    /// Generate a unified range proof.
    pub fn make(
        ciphertext: &ElGamalCiphertext,
        plaintext: u64,
        nonce: &ElementModQ,
        public_key: &ElementModP,
        selection_enc_id: &ElementModQ,
        range_bits: u32,
    ) -> Result<Self> { .. }

    /// Verify the unified range proof.
    pub fn verify(
        &self,
        ciphertext: &ElGamalCiphertext,
        public_key: &ElementModP,
        selection_enc_id: &ElementModQ,
        range_bits: u32,
    ) -> bool { .. }
}
```

### 5.14 manifest.rs

```rust
use crate::group::ElementModQ;
use crate::hash::CryptoHashable;
use crate::error::Result;
use serde::{Serialize, Deserialize};

// ── Enums ──

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ElectionType {
    Unknown, General, PartisanPrimaryClosed, PartisanPrimaryOpen,
    Primary, Runoff, Special, Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReportingUnitType {
    Unknown, BallotBatch, BallotStyleArea, Borough, City, CityCouncil,
    CombinedPrecinct, Congressional, Country, County, CountyCouncil,
    DropBox, Judicial, Municipality, PollingPlace, Precinct, School,
    Special, SplitPrecinct, State, StateHouse, StateSenate, Township,
    Utility, Village, VoteCenter, Ward, Water, Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VoteVariationType {
    Unknown, OneOfM, Approval, Borda, Cumulative, Majority,
    NOfM, Plurality, Proportional, Range, Rcv, SuperMajority, Other,
}

// ── Data types ──

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnotatedString {
    pub annotation: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Language {
    pub value: String,
    pub language: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InternationalizedText {
    pub text: Vec<Language>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactInformation {
    pub name: Option<String>,
    pub address_line: Vec<String>,
    pub email: Vec<AnnotatedString>,
    pub phone: Vec<AnnotatedString>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeopoliticalUnit {
    pub object_id: String,
    pub name: String,
    pub reporting_unit_type: ReportingUnitType,
    pub contact_information: Option<ContactInformation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BallotStyle {
    pub object_id: String,
    pub geopolitical_unit_ids: Vec<String>,
    pub party_ids: Vec<String>,
    pub image_uri: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party {
    pub object_id: String,
    pub name: Option<InternationalizedText>,
    pub abbreviation: Option<String>,
    pub color: Option<String>,
    pub logo_uri: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub object_id: String,
    pub name: Option<InternationalizedText>,
    pub party_id: Option<String>,
    pub image_uri: Option<String>,
    pub is_write_in: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectionDescription {
    pub object_id: String,
    pub candidate_id: String,
    pub sequence_order: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContestDescription {
    pub object_id: String,
    pub electoral_district_id: String,
    pub sequence_order: u64,
    pub vote_variation: VoteVariationType,
    pub number_elected: u64,
    pub votes_allowed: Option<u64>,
    pub name: String,
    pub ballot_title: Option<InternationalizedText>,
    pub ballot_subtitle: Option<InternationalizedText>,
    pub selections: Vec<SelectionDescription>,
    pub primary_party_ids: Vec<String>,
}

impl ContestDescription {
    pub fn is_valid(&self) -> bool { .. }
}

/// A ContestDescription with placeholder selections for ElectionGuard.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContestDescriptionWithPlaceholders {
    #[serde(flatten)]
    pub contest: ContestDescription,
    pub placeholder_selections: Vec<SelectionDescription>,
}

impl ContestDescriptionWithPlaceholders {
    pub fn is_placeholder(&self, selection_id: &str) -> bool { .. }
    pub fn selection_for(&self, selection_id: &str) -> Option<&SelectionDescription> { .. }
}

/// The election manifest (immutable input).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub election_scope_id: String,
    pub spec_version: String,
    pub election_type: ElectionType,
    pub start_date: String,  // ISO 8601 string
    pub end_date: String,    // ISO 8601 string
    pub geopolitical_units: Vec<GeopoliticalUnit>,
    pub parties: Vec<Party>,
    pub candidates: Vec<Candidate>,
    pub contests: Vec<ContestDescription>,
    pub ballot_styles: Vec<BallotStyle>,
    pub name: Option<InternationalizedText>,
    pub contact_information: Option<ContactInformation>,
}

impl Manifest {
    pub fn from_json(json: &str) -> Result<Self> { .. }
    pub fn to_json(&self) -> Result<String> { .. }
    pub fn is_valid(&self) -> bool { .. }
}

impl CryptoHashable for Manifest {
    fn crypto_hash(&self) -> Result<ElementModQ> { .. }
}

// Implement CryptoHashable for all manifest types that need it:
// SelectionDescription, ContestDescription, GeopoliticalUnit, BallotStyle,
// Party, Candidate, AnnotatedString, Language, InternationalizedText

/// Internal manifest with placeholder selections applied.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InternalManifest {
    pub manifest_hash: ElementModQ,
    pub geopolitical_units: Vec<GeopoliticalUnit>,
    pub candidates: Vec<Candidate>,
    pub contests: Vec<ContestDescriptionWithPlaceholders>,
    pub ballot_styles: Vec<BallotStyle>,
}

impl InternalManifest {
    /// Build from a Manifest (auto-generates placeholders).
    pub fn from_manifest(manifest: &Manifest) -> Result<Self> { .. }

    /// Get contests for a given ballot style.
    pub fn contests_for_style(&self, style_id: &str) -> Vec<&ContestDescriptionWithPlaceholders> { .. }

    /// Get ballot style by id.
    pub fn ballot_style(&self, style_id: &str) -> Option<&BallotStyle> { .. }

    pub fn from_json(json: &str) -> Result<Self> { .. }
    pub fn to_json(&self) -> Result<String> { .. }
}

/// Generate a placeholder selection for a contest.
pub fn generate_placeholder_selection(
    contest: &ContestDescription,
    sequence_id: u64,
) -> SelectionDescription { .. }
```

### 5.15 election.rs

```rust
use crate::group::{ElementModP, ElementModQ};
use crate::error::Result;
use serde::{Serialize, Deserialize};

/// The election context containing keys and hash chain.
/// Dual-key system: K (vote encryption), K̂ (data encryption).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiphertextElectionContext {
    /// Number of guardians (n)
    pub number_of_guardians: u64,
    /// Quorum threshold (k)
    pub quorum: u64,
    /// Joint vote encryption public key K = ∏ K_i
    pub elgamal_public_key: ElementModP,
    /// Joint data encryption public key K̂ = ∏ K̂_i
    pub data_public_key: ElementModP,
    /// Hash of the manifest
    pub manifest_hash: ElementModQ,
    /// Commitment hash for public keys
    pub commitment_hash: ElementModQ,
    /// Extended base hash H_E (used as HMAC key for v2.1 hashing)
    pub extended_base_hash: ElementModQ,
    /// Parameter hash H_P
    pub parameter_hash: ElementModQ,
    /// Election base hash H_B
    pub base_hash: ElementModQ,
}

impl CiphertextElectionContext {
    /// Construct the context and compute the hash chain.
    /// H_P = H(0x00...00; 0x00, version, P, Q, G)
    /// H_B = H(H_P; 0x01, n, k, manifest_hash, commitment_hash, ...)
    /// H_E = H(H_B; 0x02, H_B, commitment_hash, extended_data)
    pub fn new(
        number_of_guardians: u64,
        quorum: u64,
        elgamal_public_key: ElementModP,
        data_public_key: ElementModP,
        commitment_hash: ElementModQ,
        manifest_hash: ElementModQ,
    ) -> Result<Self> { .. }

    pub fn from_json(json: &str) -> Result<Self> { .. }
    pub fn to_json(&self) -> Result<String> { .. }
}

/// Compute parameter hash: H_P = H(00...00; 0x00, "v2.1", P, Q, G)
pub fn compute_parameter_hash() -> Result<ElementModQ> { .. }

/// Compute base hash: H_B = H(H_P; 0x01, n, k, date, manifest_hash, commitment_hash)
pub fn compute_base_hash(
    parameter_hash: &ElementModQ,
    number_of_guardians: u64,
    quorum: u64,
    manifest_hash: &ElementModQ,
    commitment_hash: &ElementModQ,
) -> Result<ElementModQ> { .. }

/// Compute extended base hash: H_E = H(H_B; 0x02, H_B, commitment_hash, ...)
pub fn compute_extended_base_hash(
    base_hash: &ElementModQ,
    commitment_hash: &ElementModQ,
) -> Result<ElementModQ> { .. }
```

### 5.16 ballot.rs

```rust
use crate::group::{ElementModP, ElementModQ};
use crate::elgamal::{ElGamalCiphertext, HashedElGamalCiphertext};
use crate::proof::ranged::RangedChaumPedersenProof;
use crate::election::CiphertextElectionContext;
use crate::hash::CryptoHashable;
use crate::error::Result;
use serde::{Serialize, Deserialize};

/// State of a ballot in the ballot box.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BallotBoxState {
    Unknown,
    Cast,
    Spoiled,
    Challenged,
}

// ── Plaintext types ──

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlaintextBallotSelection {
    pub object_id: String,
    pub vote: u64,
    pub is_placeholder_selection: bool,
    pub extended_data: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlaintextBallotContest {
    pub object_id: String,
    pub selections: Vec<PlaintextBallotSelection>,
}

impl PlaintextBallotContest {
    pub fn is_valid(
        &self,
        expected_object_id: &str,
        expected_num_selections: u64,
        expected_num_elected: u64,
        votes_allowed: Option<u64>,
    ) -> bool { .. }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlaintextBallot {
    pub object_id: String,
    pub style_id: String,
    pub contests: Vec<PlaintextBallotContest>,
}

impl PlaintextBallot {
    pub fn from_json(json: &str) -> Result<Self> { .. }
    pub fn to_json(&self) -> Result<String> { .. }
}

// ── Ciphertext types ──

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiphertextBallotSelection {
    pub object_id: String,
    pub sequence_order: u64,
    pub description_hash: ElementModQ,
    pub ciphertext: ElGamalCiphertext,
    pub is_placeholder: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<ElementModQ>,
    pub crypto_hash: ElementModQ,
    pub proof: RangedChaumPedersenProof,
    pub extended_data: Option<ElGamalCiphertext>,
}

impl CiphertextBallotSelection {
    pub fn make(
        object_id: &str,
        sequence_order: u64,
        description_hash: &ElementModQ,
        ciphertext: ElGamalCiphertext,
        context: &CiphertextElectionContext,
        plaintext: u64,
        nonce: &ElementModQ,
        is_placeholder: bool,
    ) -> Result<Self> { .. }

    pub fn is_valid_encryption(
        &self,
        encryption_seed: &ElementModQ,
        public_key: &ElementModP,
        extended_hash: &ElementModQ,
    ) -> bool { .. }

    /// Remove secret nonce after ballot is submitted.
    pub fn clear_nonce(&mut self) { self.nonce = None; }
}

impl CryptoHashable for CiphertextBallotSelection {
    fn crypto_hash(&self) -> Result<ElementModQ> { .. }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiphertextBallotContest {
    pub object_id: String,
    pub sequence_order: u64,
    pub description_hash: ElementModQ,
    pub selections: Vec<CiphertextBallotSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<ElementModQ>,
    pub ciphertext_accumulation: ElGamalCiphertext,
    pub crypto_hash: ElementModQ,
    pub proof: RangedChaumPedersenProof,
    pub hashed_elgamal: Option<HashedElGamalCiphertext>,
}

impl CiphertextBallotContest {
    pub fn make(
        object_id: &str,
        sequence_order: u64,
        description_hash: &ElementModQ,
        selections: Vec<CiphertextBallotSelection>,
        context: &CiphertextElectionContext,
        number_selected: u64,
        number_elected: u64,
        nonce: Option<&ElementModQ>,
    ) -> Result<Self> { .. }

    /// Aggregate selection nonces.
    pub fn aggregate_nonce(&self) -> Result<ElementModQ> { .. }

    /// Accumulate selection ciphertexts (homomorphic sum).
    pub fn elgamal_accumulate(&self) -> ElGamalCiphertext { .. }

    pub fn is_valid_encryption(
        &self,
        encryption_seed: &ElementModQ,
        public_key: &ElementModP,
        extended_hash: &ElementModQ,
    ) -> bool { .. }

    pub fn clear_nonces(&mut self) {
        self.nonce = None;
        for sel in &mut self.selections { sel.clear_nonce(); }
    }
}

impl CryptoHashable for CiphertextBallotContest {
    fn crypto_hash(&self) -> Result<ElementModQ> { .. }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiphertextBallot {
    pub object_id: String,
    pub style_id: String,
    pub manifest_hash: ElementModQ,
    pub ballot_code_seed: ElementModQ,
    pub contests: Vec<CiphertextBallotContest>,
    pub ballot_code: ElementModQ,
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<ElementModQ>,
    pub crypto_hash: ElementModQ,
    pub state: BallotBoxState,
    // ── v2.1 fields ──
    pub ballot_id: Option<ElementModQ>,
    pub nonce_ciphertext: Option<HashedElGamalCiphertext>,
    pub chaining_field: Option<Vec<u8>>,
    pub selection_encryption_id: Option<ElementModQ>,
}

impl CiphertextBallot {
    pub fn make(
        object_id: &str,
        style_id: &str,
        manifest_hash: &ElementModQ,
        context: &CiphertextElectionContext,
        contests: Vec<CiphertextBallotContest>,
        nonce: Option<&ElementModQ>,
        timestamp: u64,
        ballot_code_seed: Option<&ElementModQ>,
    ) -> Result<Self> { .. }

    pub fn is_valid_encryption(
        &self,
        manifest_hash: &ElementModQ,
        public_key: &ElementModP,
        extended_hash: &ElementModQ,
    ) -> bool { .. }

    /// Strip nonces and set state to Cast.
    pub fn cast(&mut self) {
        self.state = BallotBoxState::Cast;
        self.nonce = None;
        for c in &mut self.contests { c.clear_nonces(); }
    }

    /// Strip nonces and set state to Spoiled.
    pub fn spoil(&mut self) {
        self.state = BallotBoxState::Spoiled;
        self.nonce = None;
        for c in &mut self.contests { c.clear_nonces(); }
    }

    pub fn from_json(json: &str) -> Result<Self> { .. }
    pub fn to_json(&self) -> Result<String> { .. }
    pub fn to_json_with_nonces(&self) -> Result<String> { .. }
}

/// A submitted ballot (nonces stripped, state is Cast or Spoiled).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmittedBallot(pub CiphertextBallot);

impl SubmittedBallot {
    /// Create from CiphertextBallot, stripping nonces.
    pub fn from_ciphertext(ballot: CiphertextBallot, state: BallotBoxState) -> Self { .. }

    pub fn from_json(json: &str) -> Result<Self> { .. }
    pub fn to_json(&self) -> Result<String> { .. }
}

// Deref to CiphertextBallot for read access
impl std::ops::Deref for SubmittedBallot {
    type Target = CiphertextBallot;
    fn deref(&self) -> &Self::Target { &self.0 }
}
```

### 5.17 ballot_code.rs

```rust
use crate::group::ElementModQ;
use crate::elgamal::{ElGamalCiphertext, HashedElGamalCiphertext};
use crate::error::Result;

/// Get the hash for a specific encryption device.
pub fn get_hash_for_device(
    device_uuid: u64,
    session_uuid: u64,
    launch_code: u64,
    location: &str,
) -> Result<ElementModQ> { .. }

/// Get a ballot code (rotating hash) from a seed, timestamp, and ballot hash.
pub fn get_ballot_code(
    seed: &ElementModQ,
    timestamp: u64,
    ballot_hash: &ElementModQ,
) -> Result<ElementModQ> { .. }

/// v2.1: chi_l = H(H_I; 0x28, l, alpha_1, beta_1, ..., alpha_n, beta_n, [contest_data])
pub fn compute_contest_hash(
    selection_enc_id: &ElementModQ,
    contest_index: u64,
    selections: &[&ElGamalCiphertext],
    contest_data: Option<&HashedElGamalCiphertext>,
) -> Result<ElementModQ> { .. }

/// v2.1: H_DI = H(H_E; 0x2A, S_device)
pub fn compute_device_info_hash(
    extended_hash: &ElementModQ,
    device_info: &str,
) -> Result<ElementModQ> { .. }

/// v2.1: H_C = H(H_I; 0x29, chi_1, ..., chi_m, B_C)
pub fn compute_confirmation_code(
    selection_enc_id: &ElementModQ,
    contest_hashes: &[&ElementModQ],
    chaining_field: &[u8],
) -> Result<ElementModQ> { .. }

// ── Chaining ──

/// No-chain: B_C = 0x00000000 || H_DI
pub fn build_no_chaining_field(device_info_hash: &ElementModQ) -> Vec<u8> { .. }

/// Simple-chain init: B_{C,0} = 0x00000001 || H_DI
pub fn build_simple_chain_init_field(device_info_hash: &ElementModQ) -> Vec<u8> { .. }

/// Simple-chain next: B_{C,j} = 0x00000001 || H_{j-1}
pub fn build_simple_chain_field(previous_hash: &ElementModQ) -> Vec<u8> { .. }

/// Chain init hash: H_0 = H(H_E; 0x29, B_{C,0})
pub fn compute_chain_init_hash(
    extended_hash: &ElementModQ,
    init_field: &[u8],
) -> Result<ElementModQ> { .. }

/// Chain closing: H_bar
pub fn close_chain(
    extended_hash: &ElementModQ,
    last_hash: &ElementModQ,
    init_field: &[u8],
) -> Result<ElementModQ> { .. }
```

### 5.18 guardian.rs

```rust
use crate::group::{ElementModP, ElementModQ};
use crate::proof::ChaumPedersenProof;
use crate::election::CiphertextElectionContext;
use crate::error::Result;
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

/// A guardian's complete key set: vote key pair, data key pair, communication key pair.
#[derive(Clone)]
pub struct GuardianKeySet {
    /// Guardian's sequential index (1-based).
    pub guardian_index: u64,
    /// Vote encryption key pair (K_i, s_i) where K_i = g^{s_i}
    pub vote_key_pair: GuardianKeyPair,
    /// Data encryption key pair (K̂_i, ŝ_i) where K̂_i = g^{ŝ_i}
    pub data_key_pair: GuardianKeyPair,
    /// Communication key pair for encrypted share exchange
    pub comm_key_pair: GuardianKeyPair,
    /// Vote polynomial coefficients for Shamir sharing
    pub vote_polynomial: Vec<ElementModQ>,
    /// Data polynomial coefficients for Shamir sharing
    pub data_polynomial: Vec<ElementModQ>,
}

/// A guardian's key pair with Schnorr proof of possession.
#[derive(Clone)]
pub struct GuardianKeyPair {
    pub secret_key: ElementModQ,
    pub public_key: ElementModP,
}

impl Drop for GuardianKeyPair {
    fn drop(&mut self) { self.secret_key.zeroize(); }
}

/// Schnorr proof of knowledge of a discrete log: proves knowledge of s where K = g^s.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchnorrProof {
    pub public_key: ElementModP,
    pub commitment: ElementModP,
    pub challenge: ElementModQ,
    pub response: ElementModQ,
}

/// Consolidated Schnorr proof for all polynomial coefficients.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsolidatedSchnorrProof {
    pub proofs: Vec<SchnorrProof>,
}

/// A share of a guardian's secret, encrypted for another guardian.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedShare {
    pub owner_id: u64,
    pub designated_id: u64,
    pub encrypted_value: Vec<u8>,
}

/// A decrypted share fragment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptedShare {
    pub owner_id: u64,
    pub designated_id: u64,
    pub value: ElementModQ,
}

/// Public record for a guardian (published after key ceremony).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianRecord {
    pub guardian_index: u64,
    pub vote_public_key: ElementModP,
    pub data_public_key: ElementModP,
    pub vote_schnorr_proof: ConsolidatedSchnorrProof,
    pub data_schnorr_proof: ConsolidatedSchnorrProof,
    pub record_hash: ElementModQ,
}

impl GuardianKeySet {
    /// Generate a guardian's full key set including polynomial coefficients.
    pub fn generate<R: rand_core::CryptoRngCore>(
        rng: &mut R,
        guardian_index: u64,
        quorum: u64,
    ) -> Self { .. }

    /// Evaluate the vote polynomial at point x (for share generation).
    pub fn evaluate_vote_polynomial(&self, x: &ElementModQ) -> ElementModQ { .. }

    /// Evaluate the data polynomial at point x.
    pub fn evaluate_data_polynomial(&self, x: &ElementModQ) -> ElementModQ { .. }

    /// Generate Schnorr proofs for all polynomial coefficients.
    pub fn generate_schnorr_proofs(
        &self,
        parameter_hash: &ElementModQ,
    ) -> Result<(ConsolidatedSchnorrProof, ConsolidatedSchnorrProof)> { .. }

    /// Encrypt a share for another guardian.
    pub fn encrypt_share_for(
        &self,
        designated_guardian_index: u64,
        designated_comm_public_key: &ElementModP,
        parameter_hash: &ElementModQ,
    ) -> Result<EncryptedShare> { .. }
}

/// Decrypt a received share using this guardian's communication secret key.
pub fn decrypt_share(
    encrypted_share: &EncryptedShare,
    comm_secret_key: &ElementModQ,
    sender_comm_public_key: &ElementModP,
    parameter_hash: &ElementModQ,
) -> Result<DecryptedShare> { .. }

/// Verify a Schnorr proof.
pub fn verify_schnorr_proof(
    proof: &SchnorrProof,
    parameter_hash: &ElementModQ,
) -> bool { .. }

/// Compute the joint election public key from all guardian public keys.
pub fn compute_joint_key(
    guardian_public_keys: &[&ElementModP],
) -> ElementModP { .. }

/// Compute the commitment hash from all guardian polynomial commitments.
pub fn compute_commitment_hash(
    base_hash: &ElementModQ,
    vote_commitments: &[Vec<&ElementModP>],
    data_commitments: &[Vec<&ElementModP>],
) -> Result<ElementModQ> { .. }

/// Build a guardian record for publication.
pub fn build_guardian_record(
    key_set: &GuardianKeySet,
    base_hash: &ElementModQ,
    parameter_hash: &ElementModQ,
) -> Result<GuardianRecord> { .. }

/// Compute Lagrange interpolation coefficient for a guardian.
pub fn compute_lagrange_coefficient(
    guardian_index: u64,
    available_guardians: &[u64],
) -> Result<ElementModQ> { .. }
```

### 5.19 encrypt.rs

```rust
use crate::group::{ElementModP, ElementModQ};
use crate::elgamal::{ElGamalCiphertext, HashedElGamalCiphertext};
use crate::ballot::*;
use crate::manifest::*;
use crate::election::CiphertextElectionContext;
use crate::precompute::PrecomputeBuffer;
use crate::error::Result;
use serde::{Serialize, Deserialize};

/// Identifies a unique encryption device.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionDevice {
    pub device_uuid: u64,
    pub session_uuid: u64,
    pub launch_code: u64,
    pub location: String,
}

impl EncryptionDevice {
    pub fn new(device_uuid: u64, session_uuid: u64, launch_code: u64, location: &str) -> Self { .. }
    pub fn hash(&self) -> Result<ElementModQ> { .. }
}

/// Configuration for ballot encryption.
#[derive(Clone, Debug)]
pub struct EncryptionConfig {
    /// Whether to use confirmation code chaining (v2.1).
    pub use_chaining: bool,
    /// Whether to compute proofs during encryption.
    pub compute_proofs: bool,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self { use_chaining: true, compute_proofs: true }
    }
}

/// Stateful ballot encryption mediator.
/// Holds context, manifest, and optional precompute buffer.
pub struct EncryptionMediator {
    context: CiphertextElectionContext,
    internal_manifest: InternalManifest,
    device: EncryptionDevice,
    config: EncryptionConfig,
    precompute: Option<PrecomputeBuffer>,
    /// Previous ballot hash for chaining (None = first ballot).
    chain_state: Option<ElementModQ>,
}

impl EncryptionMediator {
    pub fn new(
        context: CiphertextElectionContext,
        internal_manifest: InternalManifest,
        device: EncryptionDevice,
        config: EncryptionConfig,
    ) -> Result<Self> { .. }

    /// Attach a precompute buffer for faster encryption.
    pub fn set_precompute_buffer(&mut self, buffer: PrecomputeBuffer) { .. }

    /// Encrypt a plaintext ballot.
    pub fn encrypt_ballot(
        &mut self,
        ballot: &PlaintextBallot,
    ) -> Result<CiphertextBallot> { .. }

    /// Encrypt and immediately submit (cast) a ballot.
    pub fn encrypt_and_cast(
        &mut self,
        ballot: &PlaintextBallot,
    ) -> Result<SubmittedBallot> { .. }
}

// ── Standalone encryption functions ──

/// Encrypt a single selection.
pub fn encrypt_selection(
    selection: &PlaintextBallotSelection,
    description: &SelectionDescription,
    context: &CiphertextElectionContext,
    nonce: &ElementModQ,
    is_placeholder: bool,
) -> Result<CiphertextBallotSelection> { .. }

/// Encrypt a single contest with all its selections.
pub fn encrypt_contest(
    contest: &PlaintextBallotContest,
    description: &ContestDescriptionWithPlaceholders,
    context: &CiphertextElectionContext,
    nonce: &ElementModQ,
) -> Result<CiphertextBallotContest> { .. }

/// Encrypt a full ballot.
pub fn encrypt_ballot(
    ballot: &PlaintextBallot,
    internal_manifest: &InternalManifest,
    context: &CiphertextElectionContext,
    ballot_code_seed: &ElementModQ,
    nonce: Option<&ElementModQ>,
    timestamp: u64,
) -> Result<CiphertextBallot> { .. }
```

### 5.20 decryption.rs

```rust
use crate::group::{ElementModP, ElementModQ};
use crate::elgamal::ElGamalCiphertext;
use crate::error::Result;
use serde::{Serialize, Deserialize};

/// A decryption proof for a single selection by a single guardian.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionProof {
    pub pad: ElementModP,
    pub data: ElementModP,
    pub challenge: ElementModQ,
    pub response: ElementModQ,
}

impl DecryptionProof {
    /// v2.1 commitment hash: d_i = H(H_E; 0x30, ...)
    pub fn compute_commitment_hash(
        extended_hash: &ElementModQ,
        contest_index: u64,
        selection_index: u64,
        guardian_index: u64,
        ciphertext_pad: &ElementModP,  // A
        ciphertext_data: &ElementModP, // B
        proof_pad: &ElementModP,       // a_i
        proof_data: &ElementModP,      // b_i
        partial_decryption: &ElementModP, // M_i
        available_guardians: &[u64],
    ) -> Result<ElementModQ> { .. }

    /// v2.1 decryption challenge: c = H_q(H_E; 0x31, ...)
    pub fn compute_decryption_challenge(
        extended_hash: &ElementModQ,
        contest_index: u64,
        selection_index: u64,
        ciphertext_pad: &ElementModP,
        ciphertext_data: &ElementModP,
        combined_pad: &ElementModP,
        combined_data: &ElementModP,
        combined_decryption: &ElementModP,
    ) -> Result<ElementModQ> { .. }

    /// v2.1 contest data commitment hash: d_i = H(H_I; 0x32, ...)
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
    ) -> Result<ElementModQ> { .. }

    /// Verify the decryption proof.
    pub fn is_valid(
        &self,
        ciphertext: &ElGamalCiphertext,
        public_key: &ElementModP,
        partial_decryption: &ElementModP,
        extended_hash: &ElementModQ,
        contest_index: u64,
        selection_index: u64,
    ) -> bool { .. }
}

/// Compute Lagrange coefficient w_i for guardian i among available set.
/// w_i = ∏_{j ∈ S, j≠i} j / (j - i) mod Q
pub fn compute_lagrange_coefficient(
    guardian_index: u64,
    available_guardians: &[u64],
) -> Result<ElementModQ> { .. }

/// Combine partial decryptions into a full decryption.
/// M = ∏ M_i^{w_i} mod P
pub fn combine_partial_decryptions(
    partial_decryptions: &[&ElementModP],
    lagrange_coefficients: &[&ElementModQ],
) -> ElementModP { .. }
```

### 5.21 discrete_log.rs

```rust
use crate::group::{ElementModP, ElementModQ};
use crate::error::Result;
use std::collections::HashMap;

/// Baby-step/giant-step discrete log solver.
/// Finds x such that base^x = target (mod P), for x ∈ [0, max_exp].
///
/// Unlike C++ singleton, this is an explicit struct you create and reuse.
pub struct DiscreteLogTable {
    base: ElementModP,
    table: HashMap<Vec<u8>, u64>,
    baby_step_size: u64,
    max_exp: u64,
}

impl DiscreteLogTable {
    /// Build a discrete log table for the given base.
    /// baby_step_size = sqrt(max_exp), table size ≈ baby_step_size entries.
    pub fn new(base: &ElementModP, max_exp: u64) -> Self { .. }

    /// Build using the standard generator G.
    pub fn with_generator(max_exp: u64) -> Self { .. }

    /// Solve: find x such that base^x ≡ target (mod P), or Error if not found.
    pub fn solve(&self, target: &ElementModP) -> Result<u64> { .. }
}
```

### 5.22 precompute.rs

```rust
use crate::group::{ElementModP, ElementModQ};
use crate::error::Result;
use std::collections::VecDeque;
use std::sync::Mutex;

/// Precomputed encryption triple: (r, g^r, K^r).
pub struct PrecomputedEncryption {
    pub secret: ElementModQ,
    pub pad: ElementModP,       // g^r
    pub blinding_factor: ElementModP, // K^r
}

impl PrecomputedEncryption {
    pub fn generate(public_key: &ElementModP) -> Self { .. }
}

/// Precomputed fake disjunctive commitments for proof generation.
pub struct PrecomputedFakeDisjunctiveCommitments {
    pub secret1: ElementModQ,
    pub secret2: ElementModQ,
    pub pad: ElementModP,
    pub data_zero: ElementModP,
    pub data_one: ElementModP,
}

impl PrecomputedFakeDisjunctiveCommitments {
    pub fn generate(public_key: &ElementModP) -> Self { .. }
}

/// A complete set of precomputed values for one selection encryption.
pub struct PrecomputedSelection {
    pub encryption: PrecomputedEncryption,
    pub proof: PrecomputedEncryption,
    pub fake_proof: PrecomputedFakeDisjunctiveCommitments,
}

/// Thread-safe precomputation buffer.
/// Generates encryption precomputes in the background.
pub struct PrecomputeBuffer {
    public_key: ElementModP,
    max_queue_size: u32,
    encryption_queue: Mutex<VecDeque<PrecomputedEncryption>>,
    selection_queue: Mutex<VecDeque<PrecomputedSelection>>,
}

impl PrecomputeBuffer {
    pub fn new(public_key: &ElementModP, max_queue_size: u32) -> Self { .. }

    /// Fill the queues synchronously.
    pub fn populate(&self) { .. }

    /// Get the next precomputed encryption, generating one if queue is empty.
    pub fn get_precomputed_encryption(&self) -> PrecomputedEncryption { .. }

    /// Pop a precomputed encryption if available.
    pub fn pop_precomputed_encryption(&self) -> Option<PrecomputedEncryption> { .. }

    /// Get the next precomputed selection, generating one if queue is empty.
    pub fn get_precomputed_selection(&self) -> PrecomputedSelection { .. }

    /// Pop a precomputed selection if available.
    pub fn pop_precomputed_selection(&self) -> Option<PrecomputedSelection> { .. }

    pub fn current_queue_size(&self) -> u32 { .. }
    pub fn max_queue_size(&self) -> u32 { .. }
    pub fn clear(&self) { .. }
}
```

### 5.23 serialize.rs

```rust
use crypto_bigint::{U256, U4096};
use serde::{Deserializer, Serializer};

/// Serde module for serializing U4096 as hex string.
pub mod u4096_hex {
    pub fn serialize<S: Serializer>(value: &U4096, s: S) -> Result<S::Ok, S::Error> { .. }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U4096, D::Error> { .. }
}

/// Serde module for serializing U256 as hex string.
pub mod u256_hex {
    pub fn serialize<S: Serializer>(value: &U256, s: S) -> Result<S::Ok, S::Error> { .. }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U256, D::Error> { .. }
}
```

### 5.24 lib.rs — Crate root

```rust
//! ElectionGuard Core2 — Rust implementation of the ElectionGuard v2.1 spec.
//!
//! End-to-end verifiable encrypted voting using exponential ElGamal
//! homomorphic encryption, threshold cryptography, and HMAC-SHA-256 hash chains.

pub mod error;
pub mod group;
pub mod hash;
pub mod hmac;
pub mod kdf;
pub mod nonces;
pub mod elgamal;
pub mod proof;
pub mod manifest;
pub mod election;
pub mod ballot;
pub mod ballot_code;
pub mod guardian;
pub mod encrypt;
pub mod decryption;
pub mod discrete_log;
pub mod precompute;
pub mod serialize;

// Re-export core types at crate root for convenience.
pub use error::{Error, Result};
pub use group::{ElementModP, ElementModQ};
pub use elgamal::{ElGamalCiphertext, ElGamalKeyPair, HashedElGamalCiphertext};
pub use election::CiphertextElectionContext;
pub use ballot::{PlaintextBallot, CiphertextBallot, SubmittedBallot, BallotBoxState};
pub use manifest::{Manifest, InternalManifest};
pub use encrypt::{EncryptionDevice, EncryptionMediator};
pub use guardian::{GuardianKeySet, GuardianRecord};
```

---

## 6. Error Handling Strategy

| Layer | Error Approach |
|-------|---------------|
| Group arithmetic | `Result<ElementModP>` / `Result<ElementModQ>` for division-by-zero, out-of-range |
| Hash functions | `Result<ElementModQ>` — infallible in practice but propagated for consistency |
| ElGamal encrypt | Returns value directly (infallible given valid inputs) |
| Proofs `make` | `Result<Proof>` — can fail if plaintext out of range |
| Proofs `verify` | Returns `bool` — never errors, just valid or not |
| Election context | `Result<Context>` — hash chain computation can fail |
| Ballot encryption | `Result<CiphertextBallot>` — manifest validation, proof generation |
| Serialization | `Result<String>` / `Result<T>` wrapping serde errors |
| DiscreteLog | `Result<u64>` — `DiscreteLogNotFound` if exhausted |

**Rule**: Library code never panics. All `unwrap()` calls must be provably safe with a comment.

---

## 7. Test Strategy

### Layer 0: Group & Constants (Critical Foundation)
```
tests/group_tests.rs:
  - Known-answer tests: P, Q, G, R match hex values from C++ constants.h
  - Arithmetic identity: a + 0 = a, a * 1 = a, a * a^-1 = 1
  - Modular reduction: values >= P/Q are correctly reduced
  - Edge cases: 0, 1, P-1, Q-1
  - g^Q ≡ 1 mod P (generator order)
  - Serialization round-trip: bytes → element → bytes
  - Property tests (proptest): associativity, commutativity, distributivity
```

### Layer 1: Hash & HMAC
```
tests/hash_tests.rs:
  - Known-answer: hash_elems_v21 with specific inputs → expected output
  - Domain separation: different DS bytes produce different hashes
  - Parameter hash matches C++ H_P computation
  - HMAC matches standard test vectors (RFC 4231)
```

### Layer 2: ElGamal
```
tests/elgamal_tests.rs:
  - Encrypt/decrypt round-trip (known secret key)
  - Homomorphic property: decrypt(encrypt(a) ⊕ encrypt(b)) = a + b
  - Hashed ElGamal encrypt/decrypt round-trip
  - Different nonces produce different ciphertexts
```

### Layer 3: Proofs
```
tests/proof_tests.rs:
  - Disjunctive proof: valid for plaintext 0 and 1, invalid for 2
  - Ranged proof: valid for [0, limit], invalid for limit+1
  - Constant proof: valid for correct constant, invalid for wrong constant
  - Serialization round-trip for all proof types
```

### Layer 4: Election & Manifest
```
tests/election_tests.rs:
  - Hash chain: H_P → H_B → H_E matches known values
  - Context serialization round-trip
  - Manifest validation (valid and invalid manifests)
  - InternalManifest placeholder generation
```

### Layer 5: Ballot & Encryption
```
tests/ballot_tests.rs:
  - PlaintextBallot from JSON
  - Single selection encryption + proof verification
  - Contest encryption + accumulation + proof verification
  - Full ballot encryption + all proofs valid
  - Nonce clearing on cast/spoil

tests/encrypt_tests.rs:
  - EncryptionMediator: encrypt sequence of ballots
  - Confirmation code chaining
  - Precompute buffer integration
```

### Layer 6: Guardian & Key Ceremony
```
tests/guardian_tests.rs:
  - Key generation + Schnorr proof verification
  - Polynomial evaluation at known points
  - Share encryption/decryption round-trip
  - Joint key computation
  - Lagrange interpolation with known values
```

### Layer 7: End-to-End
```
tests/e2e_tests.rs:
  - Full election lifecycle:
    1. Create manifest
    2. Generate guardian keys (n=3, k=2)
    3. Perform key ceremony (share exchange)
    4. Build election context
    5. Encrypt 10 ballots
    6. Submit (cast/spoil)
    7. Tally (homomorphic accumulation)
    8. Decrypt tally (threshold decryption with 2 of 3 guardians)
    9. Verify all proofs
    10. Verify tally matches expected plaintext totals
```

**Test Ratio Target**: 60% unit, 30% integration, 10% e2e.

---

## 8. Implementation Order

Build bottom-up. Each phase should compile and pass all tests before proceeding.

### Phase 1: Foundation (group + error + serialize)
```
Files: src/error.rs, src/group/constants.rs, src/group/mod.rs, src/serialize.rs, src/lib.rs
Tests: tests/group_tests.rs
Goal: ElementModP/ElementModQ arithmetic works. All known-answer tests pass.
Effort: HIGH — this is the hardest phase (bignum wrangling).
```

### Phase 2: Cryptographic Utilities (hash + hmac + kdf + nonces)
```
Files: src/hmac.rs, src/hash.rs, src/kdf.rs, src/nonces.rs
Tests: tests/hash_tests.rs
Goal: hash_elems_v21 produces correct outputs. HMAC matches RFC vectors.
```

### Phase 3: ElGamal Encryption
```
Files: src/elgamal.rs
Tests: tests/elgamal_tests.rs
Goal: Encrypt/decrypt round-trips. Homomorphic addition works.
```

### Phase 4: Zero-Knowledge Proofs
```
Files: src/proof/mod.rs, disjunctive.rs, constant.rs, ranged.rs, unified_range.rs
Tests: tests/proof_tests.rs
Goal: All proof types generate and verify correctly.
```

### Phase 5: Election Domain (manifest + election context)
```
Files: src/manifest.rs, src/election.rs
Tests: tests/election_tests.rs
Goal: Manifest parsing, hash chain computation, context construction.
```

### Phase 6: Ballot Types & Codes
```
Files: src/ballot.rs, src/ballot_code.rs
Tests: tests/ballot_tests.rs
Goal: Ballot encryption and confirmation code computation.
```

### Phase 7: Guardian & Key Ceremony
```
Files: src/guardian.rs
Tests: tests/guardian_tests.rs
Goal: Key generation, Schnorr proofs, share exchange, joint key computation.
```

### Phase 8: Encryption Mediator
```
Files: src/encrypt.rs
Tests: tests/encrypt_tests.rs
Goal: Full ballot encryption pipeline with chaining.
```

### Phase 9: Decryption & Discrete Log
```
Files: src/decryption.rs, src/discrete_log.rs
Tests: (in e2e)
Goal: Partial decryption, proof verification, tally decryption.
```

### Phase 10: Precompute & Performance
```
Files: src/precompute.rs
Tests: benches/group_ops.rs, benches/encrypt.rs
Goal: Precompute buffer working. Performance benchmarks established.
```

### Phase 11: End-to-End Integration
```
Tests: tests/e2e_tests.rs
Goal: Full election lifecycle passes.
```

---

## 9. Key Implementation Notes

### 9.1 Bignum Constants Transcription

The C++ constants are defined as 64-element `uint64_t` arrays in **little-endian limb order**
(least significant limb first). `crypto-bigint::U4096` uses **big-endian byte order** for
`from_be_hex()` / `from_be_bytes()`. The implementer must:

1. Read the `P_ARRAY_REVERSE`, `G_ARRAY_REVERSE`, `R_ARRAY_REVERSE` from `constants.h`
2. Reverse the limb order (to big-endian limbs)
3. Convert each limb to 8 big-endian bytes
4. Concatenate into 512 bytes
5. Use `U4096::from_be_bytes()` or define as hex literal via `U4096::from_be_hex("...")`

### 9.2 Hash Serialization Format (v2.1)

The hash function serializes arguments as:
- **ElementModP**: 512 bytes, big-endian (MSB first)
- **ElementModQ**: 32 bytes, big-endian
- **u64**: 4 bytes, big-endian (truncated to u32 — C++ casts to uint32_t)
- **String**: 4-byte BE length prefix + UTF-8 bytes
- **Vec<u8>**: 4-byte BE length prefix + raw bytes
- **null**: 4 zero bytes (0x00000000)

The HMAC key is always the 32-byte big-endian representation of the key ElementModQ.

### 9.3 Zeroize Policy

Types that hold secret material and MUST implement `Zeroize` + `ZeroizeOnDrop`:
- `ElementModQ` (always — it may hold nonces, secret keys, or hash outputs)
- `ElGamalKeyPair` (via manual Drop that zeroizes secret_key)
- `GuardianKeyPair` (same)
- `PrecomputedEncryption.secret`
- `PrecomputedFakeDisjunctiveCommitments.secret1`, `.secret2`

### 9.4 No Async (Initially)

The C++ code uses `AsyncSemaphore` for `DiscreteLog` and background precompute threads.
The Rust port should use `std::sync::Mutex` for thread safety but NOT async/await.
Background precomputation can use `std::thread::spawn` if needed, but start synchronous.

### 9.5 No BSON/MsgPack

The C++ code supports BSON and MsgPack serialization via nlohmann-json. The Rust port
supports **JSON only** via serde. BSON/MsgPack can be added later by adding the
`bson` / `rmp-serde` crates as optional features.

---

## 10. Cross-Reference: C++ → Rust Module Mapping

| C++ Header | Rust Module | Key Changes |
|-----------|-------------|-------------|
| `group.hpp` | `group/mod.rs` | `U4096`/`U256` instead of raw arrays; `LazyLock` instead of function-statics |
| `constants.h` | `group/constants.rs` | Hex literals instead of C arrays |
| `hash.hpp` | `hash.rs` | `HashableValue` enum instead of `std::variant`; trait instead of virtual |
| `hmac.hpp` | `hmac.rs` | Direct `hmac` crate instead of HACL* |
| `kdf.hpp` | `kdf.rs` | Same algorithm, Rust types |
| `elgamal.hpp` | `elgamal.rs` | Separate struct per ciphertext type |
| `chaum_pedersen.hpp` | `proof/*.rs` | Split into submodules by proof type |
| `election.hpp` | `election.rs` | Direct struct fields instead of pimpl |
| `manifest.hpp` | `manifest.rs` | Flat structs with `#[derive(Serialize)]` |
| `ballot.hpp` | `ballot.rs` | `Option<ElementModQ>` for nullable nonces |
| `ballot_code.hpp` | `ballot_code.rs` | Free functions, same API |
| `encrypt.hpp` | `encrypt.rs` | `EncryptionMediator` owns state explicitly |
| `guardian.hpp` | `guardian.rs` | Single module, explicit polynomial vectors |
| `decryption.hpp` | `decryption.rs` | Same static methods as associated functions |
| `discrete_log.hpp` | `discrete_log.rs` | Explicit struct instead of singleton |
| `precompute_buffers.hpp` | `precompute.rs` | `Mutex<VecDeque>` instead of singleton |
| `nonces.hpp` | `nonces.rs` | Same API, `&mut self` for `next()` |
| `crypto_hashable.hpp` | `hash.rs` (trait) | `CryptoHashable` trait |
| `election_object_base.hpp` | (inline) | Just `object_id: String` field on structs |

---

## 11. Success Criteria

The Rust port is complete when:

1. **`cargo build`** compiles with zero warnings
2. **`cargo test`** passes all tests including e2e
3. **`cargo clippy`** produces zero warnings
4. **Group arithmetic** matches C++ known-answer tests exactly (bit-for-bit)
5. **Hash chain** (H_P → H_B → H_E) matches C++ output for same inputs
6. **Full election lifecycle** works: keygen → encrypt → tally → decrypt → verify
7. **All proofs verify** (disjunctive, ranged, constant, unified range)
8. **JSON serialization** round-trips correctly for all types
9. **No panics** in library code (all paths return `Result`)
10. **Secret material** is zeroized on drop (verified by zeroize derives)
