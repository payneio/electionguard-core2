# ElectionGuard Core2 (Rust)

A Rust implementation of the [ElectionGuard](https://www.electionguard.vote/) v2.1
cryptographic voting SDK. Provides end-to-end verifiable election encryption,
threshold key ceremonies, homomorphic tallying, and zero-knowledge proof
generation/verification.

## Overview

This crate implements the full ElectionGuard v2.1 specification:

- **4096-bit group arithmetic** over the standard ElectionGuard prime group
  (RFC 3526 Group 15) using constant-time operations via `crypto-bigint`
- **Exponential ElGamal encryption** with homomorphic addition
- **Hashed ElGamal** for arbitrary-length data (contest data, key shares)
- **Zero-knowledge proofs**: Disjunctive Chaum-Pedersen (0-or-1),
  Constant (sum verification), Ranged, and Unified Range
- **Threshold key ceremony** with Shamir secret sharing, Schnorr proofs,
  and encrypted share exchange
- **Ballot encryption** with confirmation code chaining
- **Homomorphic tally accumulation** (add ciphertexts without decrypting)
- **Threshold decryption** with Lagrange interpolation and compensated
  decryption for missing guardians
- **Baby-step/giant-step discrete log** solver for tally recovery
- **Precomputation buffers** for batched encryption performance
- **Zeroize** on all secret material (keys, nonces, polynomial coefficients)

## Quick Start

### Build

```bash
cargo build --release
```

Requires Rust 1.85+ (2024 edition). The `--release` flag is strongly
recommended -- 4096-bit modular arithmetic is 10-20x faster with optimizations.

### Test

```bash
cargo test --release
```

466 tests covering 92% of lines, including 5 end-to-end integration tests
that exercise the full election lifecycle.

### Run the Election Simulator

```bash
cargo run --release -- --guardians 3 --threshold 2 --ballots 10 --spoil 2 --seed 42
```

See [SIMULATING-A-VOTE.md](SIMULATING-A-VOTE.md) for full simulator documentation.

## Crate Structure

```
src/
  lib.rs                   Crate root, re-exports all public API
  error.rs                 Error types (thiserror)
  serialize.rs             Hex serialization for big integers (serde)
  group/
    constants.rs           4096-bit P, Q, G, R constants (hex literals)
    mod.rs                 ElementModP, ElementModQ, modular arithmetic
  hmac.rs                  HMAC-SHA-256
  hash.rs                  v2.1 spec hashing (HMAC-based, domain-separated)
  kdf.rs                   SP 800-108r1 KDF (counter mode, HMAC-SHA-256)
  nonces.rs                Deterministic nonce derivation
  elgamal.rs               ElGamal encryption (exponential + hashed)
  proof/
    mod.rs                 Base ChaumPedersenProof struct
    disjunctive.rs         Disjunctive proof (ciphertext encrypts 0 or 1)
    constant.rs            Constant proof (accumulation encrypts N)
    ranged.rs              Ranged proof (value in [0, limit])
    unified_range.rs       Unified range proof (v2.1)
  manifest.rs              Election manifest and contest descriptions
  election.rs              CiphertextElectionContext, hash chain (H_P, H_B, H_E)
  ballot.rs                Plaintext and ciphertext ballot types
  ballot_code.rs           Confirmation codes, ballot chaining
  guardian.rs              Key ceremony, Schnorr proofs, Shamir sharing
  encrypt.rs               Selection/contest/ballot encryption, EncryptionMediator
  decryption.rs            Threshold decryption, Lagrange interpolation
  discrete_log.rs          Baby-step/giant-step discrete log solver
  precompute.rs            Precomputed encryption buffers
  bin/
    simulate.rs            CLI election simulator
tests/
  group_tests.rs           Group arithmetic tests (77)
  hash_tests.rs            Hash function tests (46)
  elgamal_tests.rs         ElGamal encryption tests (20)
  proof_tests.rs           Zero-knowledge proof tests (28)
  election_tests.rs        Election context tests (27)
  ballot_tests.rs          Ballot type tests (31)
  guardian_tests.rs        Guardian/key ceremony tests (32)
  encrypt_tests.rs         Encryption pipeline tests (29)
  manifest_tests.rs        Manifest tests (24)
  e2e_tests.rs             End-to-end lifecycle tests (5)
```

## API Example

```rust
use electionguard_core2::*;
use electionguard_core2::guardian::*;
use electionguard_core2::encrypt::*;

// 1. Build a manifest and internal manifest
let manifest: Manifest = /* ... */;
let internal = InternalManifest::from_manifest(&manifest)?;

// 2. Key ceremony (3 guardians, threshold 2)
let seed = ElementModQ::from_u64(42);
let (ks1, cs1, pks1) = generate_election_key_pair("g1", 1, 2, &seed)?;
let (ks2, cs2, pks2) = generate_election_key_pair("g2", 2, 2, &seed)?;
let (ks3, cs3, pks3) = generate_election_key_pair("g3", 3, 2, &seed)?;

// 3. Compute joint key and election context
let joint_key = compute_joint_key(&[
    pks1.vote_key.clone(),
    pks2.vote_key.clone(),
    pks3.vote_key.clone(),
]);
let context = CiphertextElectionContext::new(
    3, 2, joint_key, joint_data_key, commitment_hash, manifest_hash,
)?;

// 4. Encrypt a ballot
let device = EncryptionDevice::new(1, 1, 1, "poll-1");
let mut mediator = EncryptionMediator::new(internal, context.clone(), device)?;
let submitted = mediator.encrypt_and_cast(&plaintext_ballot)?;

// 5. Decrypt with threshold k=2 of n=3
let (share1, proof1) = compute_decryption_share(&ks1.vote_key_pair.secret_key, &ciphertext);
let (share2, proof2) = compute_decryption_share(&ks2.vote_key_pair.secret_key, &ciphertext);
// ... combine with Lagrange coefficients, solve discrete log
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `crypto-bigint` 0.6 | Constant-time 4096-bit and 256-bit arithmetic |
| `hmac` + `sha2` | HMAC-SHA-256 for v2.1 hashing and KDF |
| `serde` + `serde_json` | Serialization (JSON election records) |
| `rand` + `rand_core` | Cryptographic randomness |
| `zeroize` | Secure zeroing of secret material on drop |
| `thiserror` | Error type derivation |
| `hex` | Hex encoding/decoding for big integers |
| `subtle` | Constant-time comparison |
| `clap` | CLI argument parsing (simulator binary) |

## Performance

All times measured on a single core (no parallelism) in `--release` mode:

| Operation | Approximate Time |
|-----------|-----------------|
| Single ElGamal encryption | ~200ms |
| Disjunctive proof (make) | ~800ms |
| Full ballot (3 contests, 11 selections) | ~8s |
| Key ceremony (3 guardians, k=2) | ~5s |
| Full simulation (10 ballots, 3 guardians) | ~100s |
| Full test suite (466 tests) | ~55s |

The dominant cost is modular exponentiation in the 4096-bit prime group.
This is inherent to the ElectionGuard specification and consistent across
all implementations (C++, TypeScript, Python).

## Test Coverage

```
92.11% line coverage (829/900 lines)
466 tests, 0 failures
```

Coverage measured with `cargo-tarpaulin` in release mode. The remaining ~8%
consists of:
- Defensive guards for mathematically impossible conditions (e.g., zero
  Lagrange denominators in a prime field)
- `Display`/`Debug` trait paths that tarpaulin's instrumentation misses
  in release mode
- Ballot chaining code paths only reachable through multi-device scenarios

To measure coverage yourself:

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --release --out stdout --skip-clean --timeout 600
```

## Relationship to Other Implementations

This is a Rust port of the ElectionGuard Core2 library. The repository also
contains implementations in:

- **C++** (`/src/`) -- the reference implementation
- **TypeScript/WASM** (`/bindings/typescript/`)
- **Python** (`/bindings/python/`)

All implementations target the same ElectionGuard v2.1 specification and
should produce compatible election records.

## License

MIT