pub mod constants;

use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::LazyLock;

use crypto_bigint::{Encoding, NonZero, Odd, U256, U4096};
use crypto_bigint::modular::{MontyForm, MontyParams};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::group::constants::*;

// ── Precomputed Montgomery parameters ───────────────────────────────────────

/// Precomputed MontyParams for mod P (4096-bit).
/// P_VALUE is a known odd prime; Odd::new panics if the assertion fails.
static P_PARAMS: LazyLock<MontyParams<{ U4096::LIMBS }>> = LazyLock::new(|| {
    let p_odd = Odd::new(P_VALUE).expect("P_VALUE is an odd prime");
    MontyParams::new(p_odd)
});

/// Precomputed MontyParams for mod Q (256-bit).
/// Q_VALUE is a known odd prime; Odd::new panics if the assertion fails.
static Q_PARAMS: LazyLock<MontyParams<{ U256::LIMBS }>> = LazyLock::new(|| {
    let q_odd = Odd::new(Q_VALUE).expect("Q_VALUE is an odd prime");
    MontyParams::new(q_odd)
});

// ── ElementModP ──────────────────────────────────────────────────────────────

/// An element in [0, P) — 4096-bit modular integer.
/// Used for public keys, ciphertext components, and generators.
#[derive(Clone, Serialize, Deserialize)]
pub struct ElementModP {
    /// Internal value in [0, P). Serialized as 1024-char lowercase big-endian hex.
    #[serde(with = "crate::serialize::u4096_hex")]
    value: U4096,
}

// ── ElementModP static constants ────────────────────────────────────────────

static ZERO_P: LazyLock<ElementModP> = LazyLock::new(|| ElementModP { value: U4096::ZERO });
static ONE_P: LazyLock<ElementModP> = LazyLock::new(|| ElementModP { value: U4096::ONE });
static TWO_P: LazyLock<ElementModP> =
    LazyLock::new(|| ElementModP { value: U4096::from_u64(2) });
static P_ELEM: LazyLock<ElementModP> = LazyLock::new(|| ElementModP { value: P_VALUE });
static G_ELEM: LazyLock<ElementModP> = LazyLock::new(|| ElementModP { value: G_VALUE });
static R_ELEM: LazyLock<ElementModP> = LazyLock::new(|| ElementModP { value: R_VALUE });

// ── ElementModP impl ─────────────────────────────────────────────────────────

impl ElementModP {
    /// Create from raw U4096 value. Returns `Err` if `value >= P`.
    pub fn new(value: U4096) -> Result<Self> {
        if value >= P_VALUE {
            return Err(Error::OutOfRange(format!(
                "value ({:#x?}) is >= P",
                value.to_be_bytes()[0..8].to_vec()
            )));
        }
        Ok(Self { value })
    }

    /// Create from raw U4096 with automatic mod-P reduction.
    pub fn new_unchecked(value: U4096) -> Self {
        if value < P_VALUE {
            Self { value }
        } else {
            // SAFETY: P_VALUE != 0
            let p_nz = NonZero::new(P_VALUE).expect("P_VALUE is nonzero");
            Self { value: value.rem(&p_nz) }
        }
    }

    /// Create from big-endian bytes (512 bytes).
    pub fn from_bytes_be(bytes: &[u8; MAX_P_SIZE]) -> Result<Self> {
        let value = U4096::from_be_bytes(*bytes);
        Self::new(value)
    }

    /// Export as big-endian bytes (512 bytes).
    pub fn to_bytes_be(&self) -> [u8; MAX_P_SIZE] {
        self.value.to_be_bytes()
    }

    /// Export as lowercase hex string (1024 chars).
    pub fn to_hex(&self) -> String {
        hex::encode(self.value.to_be_bytes())
    }

    /// Parse from hex string (must be exactly 1024 chars).
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        if hex_str.len() != 1024 {
            return Err(Error::Serialization(format!(
                "P hex must be 1024 chars, got {}",
                hex_str.len()
            )));
        }
        let mut bytes = [0u8; MAX_P_SIZE];
        hex::decode_to_slice(hex_str, &mut bytes)
            .map_err(|e| Error::Serialization(format!("hex decode: {}", e)))?;
        Self::from_bytes_be(&bytes)
    }

    /// Get the raw U4096 value.
    pub fn value(&self) -> &U4096 {
        &self.value
    }

    /// Returns `true` if this element is the identity (1 mod P).
    pub fn is_one(&self) -> bool {
        self.value == U4096::ONE
    }

    /// Returns `true` if this element is zero.
    pub fn is_zero(&self) -> bool {
        self.value == U4096::ZERO
    }

    // ── Well-known constants ──────────────────────────────────────────────

    pub fn zero() -> &'static Self {
        &ZERO_P
    }
    pub fn one() -> &'static Self {
        &ONE_P
    }
    pub fn two() -> &'static Self {
        &TWO_P
    }
    /// The prime P itself (for reference/display only).
    pub fn p() -> &'static Self {
        &P_ELEM
    }
    /// The generator G of the order-Q subgroup of Z*_P.
    pub fn g() -> &'static Self {
        &G_ELEM
    }
    /// The cofactor R = (P - 1) / (2Q).
    pub fn r() -> &'static Self {
        &R_ELEM
    }
}

impl PartialEq for ElementModP {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.value.ct_eq(&other.value))
    }
}

impl Eq for ElementModP {}

impl Hash for ElementModP {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.to_be_bytes().hash(state);
    }
}

impl fmt::Debug for ElementModP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ElementModP({}...{})", &self.to_hex()[..8], &self.to_hex()[1016..])
    }
}

impl fmt::Display for ElementModP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ── ElementModP arithmetic ───────────────────────────────────────────────────

/// `(a × b) mod P` — constant-time Montgomery multiplication.
pub fn mul_mod_p(a: &ElementModP, b: &ElementModP) -> ElementModP {
    let a_r = MontyForm::new(&a.value, *P_PARAMS);
    let b_r = MontyForm::new(&b.value, *P_PARAMS);
    ElementModP { value: (a_r * b_r).retrieve() }
}

/// `(base ^ exponent) mod P` — constant-time.
/// The exponent is an `ElementModQ` (256-bit); it is widened to 4096-bit for `MontyForm::pow`.
pub fn pow_mod_p(base: &ElementModP, exponent: &ElementModQ) -> ElementModP {
    // Widen the 256-bit exponent to 4096-bit (zero-extend to the high bytes).
    let exp_bytes = exponent.value.to_be_bytes(); // [u8; 32]
    let mut wide_bytes = [0u8; MAX_P_SIZE]; // 512 bytes = 4096 bits
    wide_bytes[MAX_P_SIZE - MAX_Q_SIZE..].copy_from_slice(&exp_bytes);
    let exp_wide = U4096::from_be_bytes(wide_bytes);

    let residue = MontyForm::new(&base.value, *P_PARAMS);
    ElementModP { value: residue.pow(&exp_wide).retrieve() }
}

/// `(a × b⁻¹) mod P` — constant-time. Returns `Err` if `b == 0`.
pub fn div_mod_p(a: &ElementModP, b: &ElementModP) -> Result<ElementModP> {
    let b_inv = inv_mod_p(b)?;
    Ok(mul_mod_p(a, &b_inv))
}

/// Multiplicative inverse `a⁻¹ mod P`. Returns `Err` if `a == 0`.
pub fn inv_mod_p(a: &ElementModP) -> Result<ElementModP> {
    if a.is_zero() {
        return Err(Error::Arithmetic("cannot invert 0 mod P".to_string()));
    }
    let residue = MontyForm::new(&a.value, *P_PARAMS);
    match Option::<MontyForm<{ U4096::LIMBS }>>::from(residue.inv()) {
        Some(inv) => Ok(ElementModP { value: inv.retrieve() }),
        None => Err(Error::Arithmetic("element is not invertible mod P".to_string())),
    }
}

/// `g^exponent mod P` — convenience for generator exponentiation.
pub fn g_pow(exponent: &ElementModQ) -> ElementModP {
    pow_mod_p(ElementModP::g(), exponent)
}

// ── ElementModQ ──────────────────────────────────────────────────────────────

/// An element in [0, Q) — 256-bit modular integer.
/// Used for secret keys, nonces, hash outputs, exponents.
///
/// Automatically zeroized on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct ElementModQ {
    /// Internal value in [0, Q). Serialized as 64-char lowercase big-endian hex.
    #[serde(with = "crate::serialize::u256_hex")]
    value: U256,
}

// ── ElementModQ static constants ─────────────────────────────────────────────

static ZERO_Q: LazyLock<ElementModQ> = LazyLock::new(|| ElementModQ { value: U256::ZERO });
static ONE_Q: LazyLock<ElementModQ> = LazyLock::new(|| ElementModQ { value: U256::ONE });
static TWO_Q: LazyLock<ElementModQ> =
    LazyLock::new(|| ElementModQ { value: U256::from_u64(2) });

// ── ElementModQ impl ──────────────────────────────────────────────────────────

impl ElementModQ {
    /// Create from raw U256 value. Returns `Err` if `value >= Q`.
    pub fn new(value: U256) -> Result<Self> {
        if value >= Q_VALUE {
            return Err(Error::OutOfRange("value >= Q".to_string()));
        }
        Ok(Self { value })
    }

    /// Create from raw U256 with automatic mod-Q reduction.
    pub fn new_reduced(value: U256) -> Self {
        if value < Q_VALUE {
            Self { value }
        } else {
            // SAFETY: Q_VALUE != 0
            let q_nz = NonZero::new(Q_VALUE).expect("Q_VALUE is nonzero");
            Self { value: value.rem(&q_nz) }
        }
    }

    /// Create from u64 (always valid since u64 max << Q).
    pub fn from_u64(val: u64) -> Self {
        Self { value: U256::from_u64(val) }
    }

    /// Create from big-endian bytes (32 bytes). Returns `Err` if `value >= Q`.
    pub fn from_bytes_be(bytes: &[u8; MAX_Q_SIZE]) -> Result<Self> {
        let value = U256::from_be_bytes(*bytes);
        Self::new(value)
    }

    /// Export as big-endian bytes (32 bytes).
    pub fn to_bytes_be(&self) -> [u8; MAX_Q_SIZE] {
        self.value.to_be_bytes()
    }

    /// Export as lowercase hex string (64 chars).
    pub fn to_hex(&self) -> String {
        hex::encode(self.value.to_be_bytes())
    }

    /// Parse from hex string (must be exactly 64 chars).
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        if hex_str.len() != 64 {
            return Err(Error::Serialization(format!(
                "Q hex must be 64 chars, got {}",
                hex_str.len()
            )));
        }
        let mut bytes = [0u8; MAX_Q_SIZE];
        hex::decode_to_slice(hex_str, &mut bytes)
            .map_err(|e| Error::Serialization(format!("hex decode: {}", e)))?;
        Self::from_bytes_be(&bytes)
    }

    /// Get the raw U256 value.
    pub fn value(&self) -> &U256 {
        &self.value
    }

    /// Generate a random element in [1, Q) using a cryptographically secure RNG.
    pub fn random<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
        loop {
            let mut bytes = [0u8; MAX_Q_SIZE];
            rng.fill_bytes(&mut bytes);
            let value = U256::from_be_bytes(bytes);
            // Reject 0 and values >= Q (Q ≈ 2^256, so rejection is negligibly rare).
            if value != U256::ZERO && value < Q_VALUE {
                return Self { value };
            }
        }
    }

    /// Returns `true` if this element is zero.
    pub fn is_zero(&self) -> bool {
        self.value == U256::ZERO
    }

    // ── Constants ─────────────────────────────────────────────────────────

    pub fn zero() -> &'static Self {
        &ZERO_Q
    }
    pub fn one() -> &'static Self {
        &ONE_Q
    }
    pub fn two() -> &'static Self {
        &TWO_Q
    }
}

impl PartialEq for ElementModQ {
    /// Constant-time equality comparison.
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.value.ct_eq(&other.value))
    }
}

impl Eq for ElementModQ {}

impl Hash for ElementModQ {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.to_be_bytes().hash(state);
    }
}

impl fmt::Debug for ElementModQ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ElementModQ({})", self.to_hex())
    }
}

impl fmt::Display for ElementModQ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ── ElementModQ arithmetic ───────────────────────────────────────────────────

/// `(a + b) mod Q`
pub fn add_mod_q(a: &ElementModQ, b: &ElementModQ) -> ElementModQ {
    let a_r = MontyForm::new(&a.value, *Q_PARAMS);
    let b_r = MontyForm::new(&b.value, *Q_PARAMS);
    ElementModQ { value: (a_r + b_r).retrieve() }
}

/// `(a - b) mod Q` — wraps if `a < b`.
pub fn sub_mod_q(a: &ElementModQ, b: &ElementModQ) -> ElementModQ {
    let a_r = MontyForm::new(&a.value, *Q_PARAMS);
    let b_r = MontyForm::new(&b.value, *Q_PARAMS);
    ElementModQ { value: (a_r - b_r).retrieve() }
}

/// `(a × b) mod Q`
pub fn mul_mod_q(a: &ElementModQ, b: &ElementModQ) -> ElementModQ {
    let a_r = MontyForm::new(&a.value, *Q_PARAMS);
    let b_r = MontyForm::new(&b.value, *Q_PARAMS);
    ElementModQ { value: (a_r * b_r).retrieve() }
}

/// `(base ^ exponent) mod Q`
pub fn pow_mod_q(base: &ElementModQ, exponent: &ElementModQ) -> ElementModQ {
    let b_r = MontyForm::new(&base.value, *Q_PARAMS);
    ElementModQ { value: b_r.pow(&exponent.value).retrieve() }
}

/// `(a × b⁻¹) mod Q`. Returns `Err` if `b == 0`.
pub fn div_mod_q(a: &ElementModQ, b: &ElementModQ) -> Result<ElementModQ> {
    let b_inv = inv_mod_q(b)?;
    Ok(mul_mod_q(a, &b_inv))
}

/// Multiplicative inverse `a⁻¹ mod Q`. Returns `Err` if `a == 0`.
pub fn inv_mod_q(a: &ElementModQ) -> Result<ElementModQ> {
    if a.is_zero() {
        return Err(Error::Arithmetic("cannot invert 0 mod Q".to_string()));
    }
    let a_r = MontyForm::new(&a.value, *Q_PARAMS);
    match Option::<MontyForm<{ U256::LIMBS }>>::from(a_r.inv()) {
        Some(inv) => Ok(ElementModQ { value: inv.retrieve() }),
        None => Err(Error::Arithmetic("element is not invertible mod Q".to_string())),
    }
}

/// `(a + b×c) mod Q` — fused multiply-add (common in proof construction).
pub fn a_plus_bc_mod_q(a: &ElementModQ, b: &ElementModQ, c: &ElementModQ) -> ElementModQ {
    let bc = mul_mod_q(b, c);
    add_mod_q(a, &bc)
}

/// `(a - b×c) mod Q` — fused multiply-subtract.
pub fn a_minus_bc_mod_q(a: &ElementModQ, b: &ElementModQ, c: &ElementModQ) -> ElementModQ {
    let bc = mul_mod_q(b, c);
    sub_mod_q(a, &bc)
}

/// `(Q - a) mod Q` — additive negation.
pub fn negate_mod_q(a: &ElementModQ) -> ElementModQ {
    if a.value == U256::ZERO {
        return ElementModQ { value: U256::ZERO };
    }
    // Q - a (no wrapping since 0 < a < Q ≤ 2^256)
    ElementModQ { value: Q_VALUE.wrapping_sub(&a.value) }
}

// ── Tests for internal helpers ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_params_initialise() {
        // Force LazyLock initialisation — panics if constants are wrong
        let _ = &*P_PARAMS;
        let _ = &*Q_PARAMS;
    }

    #[test]
    fn element_mod_p_round_trip() {
        let g = ElementModP::g();
        let bytes = g.to_bytes_be();
        let recovered = ElementModP::from_bytes_be(&bytes).unwrap();
        assert_eq!(*g, recovered);
    }

    #[test]
    fn element_mod_q_round_trip() {
        let q = ElementModQ::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let hex = q.to_hex();
        let recovered = ElementModQ::from_hex(&hex).unwrap();
        assert_eq!(q, recovered);
    }
}
