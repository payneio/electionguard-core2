//! Zero-knowledge proof types for ElectionGuard v2.1.
//!
//! All proof types use Fiat-Shamir Sigma protocols (non-interactive via HMAC hashing).
//!
//! # Proof types
//!
//! | Type | File | Purpose |
//! |------|------|---------|
//! | [`ChaumPedersenProof`]            | mod.rs          | Base sub-proof (pad, data, challenge, response) |
//! | [`DisjunctiveChaumPedersenProof`] | disjunctive.rs  | Proves ciphertext encrypts 0 or 1 |
//! | [`ConstantChaumPedersenProof`]    | constant.rs     | Proves accumulated ciphertext = constant |
//! | [`RangedChaumPedersenProof`]      | ranged.rs       | Proves value ∈ [0, range_limit] |
//! | [`UnifiedRangeProof`]             | unified_range.rs| v2.1 range proof in [0, 2^b − 1] |

use serde::{Deserialize, Serialize};

use crate::group::{ElementModP, ElementModQ};

// ── Sub-module declarations ───────────────────────────────────────────────────

pub mod disjunctive;
pub mod constant;
pub mod ranged;
pub mod unified_range;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use disjunctive::DisjunctiveChaumPedersenProof;
pub use constant::ConstantChaumPedersenProof;
pub use ranged::RangedChaumPedersenProof;
pub use unified_range::UnifiedRangeProof;

// ── ChaumPedersenProof ────────────────────────────────────────────────────────

/// A single Chaum-Pedersen sub-proof (one branch of a disjunctive proof, or a
/// standalone constant/accumulation proof).
///
/// Given a ciphertext `(α, β)` and public key `K`, this proves knowledge of a
/// witness `r` such that `α = g^r` and `β_adj = K^r` for some adjusted `β_adj`.
///
/// # Fields
///
/// | Field       | Symbol | Meaning                                      |
/// |-------------|--------|----------------------------------------------|
/// | `pad`       | `a`    | First commitment: `g^w` for random `w`.      |
/// | `data`      | `b`    | Second commitment: `K^w`.                    |
/// | `challenge` | `c`    | Fiat-Shamir challenge (from hash of context).|
/// | `response`  | `v`    | Response: `w − c·r mod Q`.                   |
///
/// # Verification equations
/// - `g^v · α^c = a`
/// - `K^v · β_adj^c = b`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChaumPedersenProof {
    /// First commitment `a = g^w`.
    pub pad: ElementModP,
    /// Second commitment `b = K^w`.
    pub data: ElementModP,
    /// Fiat-Shamir challenge `c`.
    pub challenge: ElementModQ,
    /// Response `v = w − c·r mod Q`.
    pub response: ElementModQ,
}

impl ChaumPedersenProof {
    /// Construct a proof from its components.
    pub fn new(
        pad: ElementModP,
        data: ElementModP,
        challenge: ElementModQ,
        response: ElementModQ,
    ) -> Self {
        Self { pad, data, challenge, response }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{g_pow, ElementModQ};

    #[test]
    fn chaum_pedersen_proof_construction() {
        let q = ElementModQ::from_u64(1);
        let p = g_pow(&q);
        let proof = ChaumPedersenProof::new(p.clone(), p.clone(), q.clone(), q.clone());
        assert_eq!(proof.pad, p);
        assert_eq!(proof.challenge, q);
    }
}
