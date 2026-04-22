//! Baby-step / giant-step discrete logarithm solver for ElGamal decryption.
//!
//! Finds `x` such that `base^x ≡ target (mod P)` for `x ∈ [0, max_exp]`.
//!
//! # Algorithm
//!
//! Let `n = ⌈√max_exp⌉`.
//!
//! **Baby steps** — build a lookup table:
//! ```text
//! table[base^j] = j,   j ∈ 0..n
//! ```
//!
//! **Giant step** — compute `γ = base^(−n) mod P` once.
//!
//! **Search** — for `i ∈ 0..=n`:
//! ```text
//! candidate = target · γ^i
//! if candidate ∈ table:
//!     return x = i·n + table[candidate]
//! ```
//!
//! Correctness: if `x = i·n + j` then `target · γ^i = base^(i·n+j) · base^(−i·n) = base^j`. ✓
//!
//! # Complexity
//!
//! | Phase        | Time           | Space  |
//! |--------------|----------------|--------|
//! | `new`        | O(√max\_exp) muls | O(√max\_exp) |
//! | `solve`      | O(√max\_exp) muls + O(1) hash lookups per step | O(1) extra |
//!
//! For the default `DLOG_MAX_SIZE = 5 000 000`, `n ≈ 2237`, so table construction
//! takes ≈ 2237 group multiplications.

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::group::{
    inv_mod_p, mul_mod_p, pow_mod_p, ElementModP, ElementModQ,
};
use crate::group::constants::DLOG_MAX_SIZE;

// ── DiscreteLogTable ─────────────────────────────────────────────────────────

/// Baby-step / giant-step discrete logarithm table.
///
/// Create once (which pre-computes the baby-step table), then call
/// [`DiscreteLogTable::solve`] repeatedly to look up exponents.
///
/// Unlike the C++ singleton design, this is an explicit struct you create and
/// reuse.  Use [`DiscreteLogTable::with_generator`] as the most common
/// entry-point; it builds a table for the standard generator `G`.
pub struct DiscreteLogTable {
    /// The group base element.
    base: ElementModP,
    /// Baby-step lookup table: `base^j → j` for `j ∈ 0..baby_step_size`.
    table: HashMap<ElementModP, u64>,
    /// `n = ⌈√max_exp⌉` — the baby-step stride.
    baby_step_size: u64,
    /// Maximum exponent this table can solve.
    max_exp: u64,
}

impl DiscreteLogTable {
    /// Build a discrete log table for `base` that can solve exponents up to
    /// `max_exp`.
    ///
    /// # Panics
    ///
    /// Panics if `base` is the identity element (1 mod P), which would make
    /// every exponent indistinguishable.
    pub fn new(base: &ElementModP, max_exp: u64) -> Self {
        assert!(!base.is_one(), "DiscreteLogTable: base must not be 1 mod P");

        // n = ⌈√max_exp⌉, minimum 1 to avoid division-by-zero later.
        let n: u64 = if max_exp == 0 {
            1
        } else {
            let sq = (max_exp as f64).sqrt().ceil() as u64;
            sq.max(1)
        };

        // Baby steps: table[base^j] = j for j in 0..n
        // We build iteratively with repeated multiplication to avoid n separate
        // exponentiations.
        let mut table: HashMap<ElementModP, u64> = HashMap::with_capacity((n + 1) as usize);
        let mut current = ElementModP::one().clone(); // base^0 = 1
        for j in 0..n {
            table.entry(current.clone()).or_insert(j);
            current = mul_mod_p(&current, base);
        }

        DiscreteLogTable { base: base.clone(), table, baby_step_size: n, max_exp }
    }

    /// Build a table using the standard generator `G`.
    ///
    /// Equivalent to `DiscreteLogTable::new(ElementModP::g(), max_exp)`.
    pub fn with_generator(max_exp: u64) -> Self {
        Self::new(ElementModP::g(), max_exp)
    }

    /// Build a default table using generator `G` and [`DLOG_MAX_SIZE`] as the
    /// upper bound.
    pub fn default_generator() -> Self {
        Self::with_generator(DLOG_MAX_SIZE)
    }

    /// Solve `base^x ≡ target (mod P)` and return `x`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DiscreteLogNotFound`] if no solution is found within
    /// `[0, max_exp]`.
    pub fn solve(&self, target: &ElementModP) -> Result<u64> {
        let n = self.baby_step_size;

        // Shortcut: target == 1 means x == 0
        if target.is_one() {
            return Ok(0);
        }

        // Giant step γ = base^(−n)
        let base_n = pow_mod_p(&self.base, &ElementModQ::from_u64(n));
        let giant_step = inv_mod_p(&base_n)?;

        // Search: for i = 0..=ceil(max_exp / n)
        let max_i = self.max_exp / n + 1;
        let mut current = target.clone();

        for i in 0..=max_i {
            if let Some(&j) = self.table.get(&current) {
                let x = i * n + j;
                if x <= self.max_exp {
                    return Ok(x);
                }
            }
            current = mul_mod_p(&current, &giant_step);
        }

        Err(Error::DiscreteLogNotFound(self.max_exp))
    }

    /// The maximum exponent this table can resolve.
    pub fn max_exp(&self) -> u64 {
        self.max_exp
    }

    /// The baby-step stride `n = ⌈√max_exp⌉`.
    pub fn baby_step_size(&self) -> u64 {
        self.baby_step_size
    }

    /// Current number of baby-step table entries.
    pub fn table_size(&self) -> usize {
        self.table.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{g_pow, ElementModQ};

    /// Small max_exp for tests so table construction is fast.
    const SMALL_MAX: u64 = 100;

    fn dlog_g(max_exp: u64) -> DiscreteLogTable {
        DiscreteLogTable::with_generator(max_exp)
    }

    // ── Known-answer tests ──────────────────────────────────────────────────

    #[test]
    fn dlog_zero() {
        // g^0 = 1
        let dlog = dlog_g(SMALL_MAX);
        let g0 = ElementModP::one().clone();
        assert_eq!(dlog.solve(&g0).unwrap(), 0);
    }

    #[test]
    fn dlog_one() {
        // g^1 = g
        let dlog = dlog_g(SMALL_MAX);
        let g1 = g_pow(&ElementModQ::from_u64(1));
        assert_eq!(dlog.solve(&g1).unwrap(), 1);
    }

    #[test]
    fn dlog_five() {
        // g^5 → 5
        let dlog = dlog_g(SMALL_MAX);
        let g5 = g_pow(&ElementModQ::from_u64(5));
        assert_eq!(dlog.solve(&g5).unwrap(), 5);
    }

    #[test]
    fn dlog_ten() {
        let dlog = dlog_g(SMALL_MAX);
        let g10 = g_pow(&ElementModQ::from_u64(10));
        assert_eq!(dlog.solve(&g10).unwrap(), 10);
    }

    #[test]
    fn dlog_boundary_max_exp() {
        // Exact boundary: x == max_exp
        let max = 50u64;
        let dlog = dlog_g(max);
        let target = g_pow(&ElementModQ::from_u64(max));
        assert_eq!(dlog.solve(&target).unwrap(), max);
    }

    #[test]
    fn dlog_sweep_small() {
        // Check every exponent in [0, 20]
        let dlog = dlog_g(20);
        for x in 0u64..=20 {
            let target = g_pow(&ElementModQ::from_u64(x));
            let result = dlog.solve(&target).expect("should find exponent");
            assert_eq!(result, x, "failed for x={}", x);
        }
    }

    // ── Edge cases ──────────────────────────────────────────────────────────

    #[test]
    fn dlog_not_found_returns_error() {
        // max_exp = 5, target = g^10 → not found
        let dlog = dlog_g(5);
        let target = g_pow(&ElementModQ::from_u64(10));
        assert!(matches!(dlog.solve(&target), Err(Error::DiscreteLogNotFound(5))));
    }

    #[test]
    fn dlog_max_exp_zero() {
        // max_exp = 0 → only g^0 = 1 is findable
        let dlog = dlog_g(0);
        assert_eq!(dlog.solve(ElementModP::one()).unwrap(), 0);
    }

    // ── Metadata ────────────────────────────────────────────────────────────

    #[test]
    fn dlog_metadata() {
        let dlog = dlog_g(SMALL_MAX);
        assert_eq!(dlog.max_exp(), SMALL_MAX);
        // n = ceil(sqrt(100)) = 10
        assert_eq!(dlog.baby_step_size(), 10);
        assert_eq!(dlog.table_size(), 10); // 10 entries for j=0..10
    }

    // ── Medium-range test (not too slow) ─────────────────────────────────────

    #[test]
    fn dlog_medium_range() {
        // 500 should be quick (n ≈ 23)
        let dlog = dlog_g(500);
        for x in [0u64, 1, 7, 99, 256, 499, 500] {
            let target = g_pow(&ElementModQ::from_u64(x));
            assert_eq!(dlog.solve(&target).unwrap(), x, "failed for x={}", x);
        }
    }
}
