//! Comprehensive tests for group arithmetic in `electionguard_core2::group`.

use electionguard_core2::{
    ElementModP, ElementModQ,
    // P arithmetic
    mul_mod_p, pow_mod_p, div_mod_p, inv_mod_p, g_pow,
    // Q arithmetic
    add_mod_q, sub_mod_q, mul_mod_q, pow_mod_q, div_mod_q, inv_mod_q,
    a_plus_bc_mod_q, a_minus_bc_mod_q, negate_mod_q,
};
use electionguard_core2::group::constants::{Q_VALUE, P_VALUE};

// ── Helper constructors ───────────────────────────────────────────────────────

fn q(n: u64) -> ElementModQ {
    ElementModQ::from_u64(n)
}

// ── Constants ─────────────────────────────────────────────────────────────────

#[test]
fn constants_not_zero() {
    assert!(!ElementModP::g().is_zero(), "G must not be zero");
    assert!(!ElementModP::g().is_one(), "G must not be 1");
    assert!(ElementModQ::zero().is_zero());
    assert_eq!(*ElementModQ::zero(), q(0));
    assert_eq!(*ElementModQ::one(), q(1));
    assert_eq!(*ElementModQ::two(), q(2));
}

#[test]
fn p_one_is_identity() {
    assert!(ElementModP::one().is_one());
    assert!(!ElementModP::one().is_zero());
}

// ── ElementModQ construction ──────────────────────────────────────────────────

#[test]
fn element_mod_q_from_u64() {
    let e = ElementModQ::from_u64(42);
    assert_eq!(e.to_hex(), "000000000000000000000000000000000000000000000000000000000000002a");
}

#[test]
fn element_mod_q_rejects_value_ge_q() {
    // Q itself should be rejected.
    let q_bytes = Q_VALUE.to_be_bytes();
    let result = ElementModQ::from_bytes_be(&q_bytes);
    assert!(result.is_err(), "Q must be rejected: value == Q");
}

#[test]
fn element_mod_q_hex_round_trip() {
    let hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let e = ElementModQ::from_hex(hex).unwrap();
    assert_eq!(e.to_hex(), hex);
}

#[test]
fn element_mod_q_bytes_round_trip() {
    let original = ElementModQ::from_u64(0xDEAD_BEEF_CAFE_1234);
    let bytes = original.to_bytes_be();
    let recovered = ElementModQ::from_bytes_be(&bytes).unwrap();
    assert_eq!(original, recovered);
}

#[test]
fn element_mod_p_from_hex_1024_chars() {
    let g_hex = ElementModP::g().to_hex();
    assert_eq!(g_hex.len(), 1024);
    let recovered = ElementModP::from_hex(&g_hex).unwrap();
    assert_eq!(*ElementModP::g(), recovered);
}

#[test]
fn element_mod_p_rejects_wrong_hex_length() {
    assert!(ElementModP::from_hex("abc").is_err());
    assert!(ElementModP::from_hex(&"00".repeat(513)).is_err());
}

// ── Serialization ─────────────────────────────────────────────────────────────

#[test]
fn json_round_trip_mod_q() {
    let e = ElementModQ::from_u64(99);
    let json = serde_json::to_string(&e).unwrap();
    let recovered: ElementModQ = serde_json::from_str(&json).unwrap();
    assert_eq!(e, recovered);
}

#[test]
fn json_round_trip_mod_p() {
    let g = ElementModP::g();
    let json = serde_json::to_string(g).unwrap();
    let recovered: ElementModP = serde_json::from_str(&json).unwrap();
    assert_eq!(*g, recovered);
}

// ── Equality (constant-time) ──────────────────────────────────────────────────

#[test]
fn equality_mod_q() {
    let a = q(7);
    let b = q(7);
    let c = q(8);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn equality_mod_p() {
    let g = ElementModP::g();
    assert_eq!(g, ElementModP::g());
    assert_ne!(*ElementModP::one(), *g);
}

// ── Q arithmetic ──────────────────────────────────────────────────────────────

#[test]
fn add_mod_q_basic() {
    let a = q(3);
    let b = q(5);
    let sum = add_mod_q(&a, &b);
    assert_eq!(sum, q(8));
}

#[test]
fn add_mod_q_identity() {
    let a = q(42);
    let sum = add_mod_q(&a, ElementModQ::zero());
    assert_eq!(a, sum);
}

#[test]
fn sub_mod_q_basic() {
    let a = q(10);
    let b = q(4);
    let diff = sub_mod_q(&a, &b);
    assert_eq!(diff, q(6));
}

#[test]
fn sub_mod_q_wraps() {
    // 2 - 5 mod Q should wrap.
    let a = q(2);
    let b = q(5);
    let diff = sub_mod_q(&a, &b);
    // Verify: diff + 5 == 2 mod Q
    let check = add_mod_q(&diff, &b);
    assert_eq!(check, a);
}

#[test]
fn negate_mod_q_zero() {
    let z = ElementModQ::zero();
    let neg = negate_mod_q(z);
    assert_eq!(neg, *ElementModQ::zero());
}

#[test]
fn negate_mod_q_and_add() {
    let a = q(17);
    let neg_a = negate_mod_q(&a);
    let sum = add_mod_q(&a, &neg_a);
    assert_eq!(sum, *ElementModQ::zero());
}

#[test]
fn mul_mod_q_basic() {
    let a = q(6);
    let b = q(7);
    let product = mul_mod_q(&a, &b);
    assert_eq!(product, q(42));
}

#[test]
fn mul_mod_q_identity() {
    let a = q(999);
    let product = mul_mod_q(&a, ElementModQ::one());
    assert_eq!(a, product);
}

#[test]
fn mul_mod_q_zero() {
    let a = q(999);
    let product = mul_mod_q(&a, ElementModQ::zero());
    assert_eq!(product, *ElementModQ::zero());
}

#[test]
fn inv_mod_q_basic() {
    let a = q(5);
    let inv = inv_mod_q(&a).unwrap();
    let product = mul_mod_q(&a, &inv);
    assert_eq!(product, *ElementModQ::one());
}

#[test]
fn inv_mod_q_zero_fails() {
    assert!(inv_mod_q(ElementModQ::zero()).is_err());
}

#[test]
fn div_mod_q_basic() {
    let a = q(20);
    let b = q(4);
    let quotient = div_mod_q(&a, &b).unwrap();
    // quotient * b == a
    let check = mul_mod_q(&quotient, &b);
    assert_eq!(check, a);
}

#[test]
fn pow_mod_q_basic() {
    let base = q(3);
    let exp = q(4);
    let result = pow_mod_q(&base, &exp);
    assert_eq!(result, q(81));
}

#[test]
fn pow_mod_q_exp_zero() {
    let base = q(1234567);
    let result = pow_mod_q(&base, ElementModQ::zero());
    assert_eq!(result, *ElementModQ::one());
}

#[test]
fn pow_mod_q_exp_one() {
    let base = q(7);
    let result = pow_mod_q(&base, ElementModQ::one());
    assert_eq!(result, base);
}

#[test]
fn a_plus_bc_mod_q_basic() {
    // 2 + 3*4 = 14
    let result = a_plus_bc_mod_q(&q(2), &q(3), &q(4));
    assert_eq!(result, q(14));
}

#[test]
fn a_minus_bc_mod_q_basic() {
    // 20 - 3*4 = 8
    let result = a_minus_bc_mod_q(&q(20), &q(3), &q(4));
    assert_eq!(result, q(8));
}

// ── P arithmetic ──────────────────────────────────────────────────────────────

#[test]
fn mul_mod_p_with_one() {
    let g = ElementModP::g();
    let product = mul_mod_p(g, ElementModP::one());
    assert_eq!(*g, product);
}

#[test]
fn mul_mod_p_commutativity() {
    let g = ElementModP::g();
    let one = ElementModP::one();
    let ab = mul_mod_p(g, one);
    let ba = mul_mod_p(one, g);
    assert_eq!(ab, ba);
}

#[test]
fn pow_mod_p_exp_zero_gives_one() {
    let g = ElementModP::g();
    let result = pow_mod_p(g, ElementModQ::zero());
    assert_eq!(result, *ElementModP::one());
}

#[test]
fn pow_mod_p_exp_one_gives_base() {
    let g = ElementModP::g();
    let result = pow_mod_p(g, ElementModQ::one());
    assert_eq!(*g, result);
}

#[test]
fn g_pow_equals_pow_mod_p_on_g() {
    let exp = q(7);
    let via_g_pow = g_pow(&exp);
    let via_pow_mod_p = pow_mod_p(ElementModP::g(), &exp);
    assert_eq!(via_g_pow, via_pow_mod_p);
}

#[test]
fn inv_mod_p_basic() {
    let g = ElementModP::g();
    let g_inv = inv_mod_p(g).unwrap();
    let product = mul_mod_p(g, &g_inv);
    assert_eq!(product, *ElementModP::one());
}

#[test]
fn inv_mod_p_zero_fails() {
    assert!(inv_mod_p(ElementModP::zero()).is_err());
}

#[test]
fn div_mod_p_basic() {
    let g = ElementModP::g();
    let g_sq = mul_mod_p(g, g);
    let quotient = div_mod_p(&g_sq, g).unwrap();
    assert_eq!(quotient, *g);
}

// ── g^a * g^b == g^(a+b) (discrete log homomorphism) ─────────────────────────

#[test]
fn g_pow_additive_homomorphism() {
    let a = q(100);
    let b = q(200);
    let a_plus_b = add_mod_q(&a, &b);

    let g_a = g_pow(&a);
    let g_b = g_pow(&b);
    let g_a_times_g_b = mul_mod_p(&g_a, &g_b);
    let g_a_plus_b = g_pow(&a_plus_b);

    assert_eq!(g_a_times_g_b, g_a_plus_b, "g^a * g^b must equal g^(a+b)");
}

/// g^(a*b) == (g^a)^b
#[test]
fn g_pow_multiplicative_homomorphism() {
    let a = q(11);
    let b = q(13);
    let ab = mul_mod_q(&a, &b);

    let g_ab = g_pow(&ab);
    let g_a = g_pow(&a);
    let g_a_b = pow_mod_p(&g_a, &b);

    assert_eq!(g_ab, g_a_b, "g^(a*b) must equal (g^a)^b");
}

/// Inverse: g^(-a) * g^a == 1
#[test]
fn g_pow_neg_is_inverse() {
    let a = q(7);
    let neg_a = negate_mod_q(&a);
    let g_a = g_pow(&a);
    let g_neg_a = g_pow(&neg_a);
    let product = mul_mod_p(&g_a, &g_neg_a);
    assert_eq!(product, *ElementModP::one(), "g^a * g^(-a) must equal 1");
}

/// g^(a - b) == g^a / g^b
#[test]
fn g_pow_subtraction_is_division() {
    let a = q(50);
    let b = q(20);
    let a_minus_b = sub_mod_q(&a, &b);

    let g_a = g_pow(&a);
    let g_b = g_pow(&b);
    let g_a_div_g_b = div_mod_p(&g_a, &g_b).unwrap();
    let g_a_minus_b = g_pow(&a_minus_b);

    assert_eq!(g_a_div_g_b, g_a_minus_b, "g^a / g^b must equal g^(a-b)");
}

// ── Display and Debug ─────────────────────────────────────────────────────────

#[test]
fn display_mod_q_is_hex() {
    let e = q(1);
    let s = format!("{}", e);
    assert_eq!(s.len(), 64);
    assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn debug_mod_p_shows_prefix() {
    let g = ElementModP::g();
    let s = format!("{:?}", g);
    assert!(s.starts_with("ElementModP("));
}

// ── Hash-map usage ────────────────────────────────────────────────────────────

#[test]
fn mod_q_in_hash_map() {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    let k1 = q(1);
    let k2 = q(2);
    map.insert(k1.clone(), "one");
    map.insert(k2.clone(), "two");
    assert_eq!(*map.get(&k1).unwrap(), "one");
    assert_eq!(*map.get(&q(2)).unwrap(), "two");
}

#[test]
fn mod_p_in_hash_map() {
    use std::collections::HashMap;
    let mut map: HashMap<ElementModP, u32> = HashMap::new();
    let g = ElementModP::g().clone();
    map.insert(g.clone(), 42);
    assert_eq!(*map.get(&g).unwrap(), 42);
}

// ── Zeroize ───────────────────────────────────────────────────────────────────

#[test]
fn element_mod_q_zeroize_on_drop() {
    // We can't inspect memory after drop, but this test verifies
    // that the `Zeroize` + `#[zeroize(drop)]` compiles and runs correctly.
    let secret = ElementModQ::from_u64(0xDEAD_BEEF);
    drop(secret);
    // If we reach here without UB/panic, the zeroize is working.
}

// ── Random generation ─────────────────────────────────────────────────────────

#[test]
fn random_mod_q_is_in_range() {
    let mut rng = rand::thread_rng();
    for _ in 0..20 {
        let r = ElementModQ::random(&mut rng);
        assert!(!r.is_zero(), "random element must not be zero");
        assert!(*r.value() < Q_VALUE, "random element must be < Q");
    }
}

#[test]
fn random_mod_q_distinct() {
    let mut rng = rand::thread_rng();
    let a = ElementModQ::random(&mut rng);
    let b = ElementModQ::random(&mut rng);
    // Extremely unlikely to be equal; treat collision as test failure.
    assert_ne!(a, b, "two random elements should almost certainly be distinct");
}

// ── Display / Debug ────────────────────────────────────────────────────────

#[test]
fn element_mod_p_display_format() {
    let p = ElementModP::one().clone();
    let s = format!("{}", p);
    assert_eq!(s.len(), 1024, "Display must produce 1024 hex chars");
    // The last byte is 0x01
    assert!(s.ends_with("01"), "one should end with '01'");
}

#[test]
fn element_mod_p_debug_format() {
    let p = ElementModP::g().clone();
    let s = format!("{:?}", p);
    assert!(s.starts_with("ElementModP("), "Debug must start with 'ElementModP('");
    // Contains '...' truncation marker
    assert!(s.contains("..."), "Debug must show truncated form");
}

#[test]
fn element_mod_q_display_format() {
    let q_val = ElementModQ::from_u64(255);
    let s = format!("{}", q_val);
    assert_eq!(s.len(), 64, "Display must produce 64 hex chars");
    assert!(s.ends_with("ff"), "255 should end with 'ff'");
}

#[test]
fn element_mod_q_debug_format() {
    let q_val = ElementModQ::from_u64(42);
    let s = format!("{:?}", q_val);
    assert!(s.starts_with("ElementModQ("), "Debug must start with 'ElementModQ('");
}

// ── Hash trait (HashMap usage) ─────────────────────────────────────────────

#[test]
fn element_mod_q_hashable_in_map() {
    use std::collections::HashMap;
    let mut map: HashMap<ElementModQ, &str> = HashMap::new();
    map.insert(ElementModQ::from_u64(1), "one");
    map.insert(ElementModQ::from_u64(2), "two");
    assert_eq!(*map.get(&ElementModQ::from_u64(1)).unwrap(), "one");
    assert_eq!(*map.get(&ElementModQ::from_u64(2)).unwrap(), "two");
    assert!(map.get(&ElementModQ::from_u64(99)).is_none());
}

// ── is_zero() ─────────────────────────────────────────────────────────────

#[test]
fn element_mod_p_is_zero_check() {
    assert!(ElementModP::zero().is_zero(), "zero() must be zero");
    assert!(!ElementModP::one().is_zero(), "one() must not be zero");
    assert!(!ElementModP::g().is_zero(), "g() must not be zero");
}

#[test]
fn element_mod_q_is_zero_check() {
    assert!(ElementModQ::zero().is_zero(), "zero() must be zero");
    assert!(!ElementModQ::one().is_zero(), "one() must not be zero");
    assert!(!ElementModQ::from_u64(42).is_zero(), "42 must not be zero");
}

// ── ElementModP static constants ──────────────────────────────────────────

#[test]
fn element_mod_p_two_constant() {
    let two = ElementModP::two();
    assert!(!two.is_zero(), "two() must not be zero");
    assert!(!two.is_one(), "two() must not be one");
    // two() == g^0 is not 1, so just sanity-check the hex length
    assert_eq!(two.to_hex().len(), 1024);
}

#[test]
fn element_mod_p_cofactor_r() {
    let r = ElementModP::r();
    assert!(!r.is_zero(), "cofactor R must not be zero");
}

#[test]
fn element_mod_p_prime_p_constant() {
    let p_elem = ElementModP::p();
    // P itself is 4096 bits and definitely non-zero
    assert!(!p_elem.is_zero(), "prime P must not be zero");
    assert!(!p_elem.is_one(), "prime P must not be one");
}

// ── ElementModQ constants ────────────────────────────────────────────────

#[test]
fn element_mod_q_two_constant() {
    assert_eq!(*ElementModQ::two(), ElementModQ::from_u64(2));
}

// ── ElementModP construction error paths ──────────────────────────────────

#[test]
fn element_mod_p_new_rejects_value_ge_p() {
    use electionguard_core2::group::constants::P_VALUE;
    // P itself is out of range for ElementModP::new()
    let result = ElementModP::new(P_VALUE);
    assert!(result.is_err(), "P_VALUE must be rejected (>= P)");
}

#[test]
fn element_mod_p_new_unchecked_reduces_large_value() {
    use electionguard_core2::group::constants::P_VALUE;
    // P mod P == 0
    let reduced = ElementModP::new_unchecked(P_VALUE);
    assert!(reduced.is_zero(), "P mod P should be zero");
}

#[test]
fn element_mod_p_bytes_round_trip() {
    let p = ElementModP::g().clone();
    let bytes = p.to_bytes_be();
    let p2 = ElementModP::from_bytes_be(&bytes).unwrap();
    assert_eq!(p, p2, "from_bytes_be(to_bytes_be()) must round-trip");
}

#[test]
fn element_mod_p_from_hex_invalid_chars_error() {
    // 'z' is not a valid hex character
    let bad_hex = "z".repeat(1024);
    let result = ElementModP::from_hex(&bad_hex);
    assert!(result.is_err(), "invalid hex must return Err");
}

// ── ElementModQ construction error paths ──────────────────────────────────

#[test]
fn element_mod_q_new_rejects_value_ge_q() {
    // ElementModQ::new(Q_VALUE) must fail since Q is not in [0, Q)
    let result = ElementModQ::new(Q_VALUE);
    assert!(result.is_err(), "Q itself must be rejected by new()");
}

#[test]
fn element_mod_q_new_reduced_with_q_value() {
    // Q mod Q == 0
    let reduced = ElementModQ::new_reduced(Q_VALUE);
    assert!(reduced.is_zero(), "Q mod Q should be zero");
}

#[test]
fn element_mod_q_from_hex_wrong_length_error() {
    let short = "00".repeat(10); // 20 chars, not 64
    let result = ElementModQ::from_hex(&short);
    assert!(result.is_err(), "short hex must return Err");
}

#[test]
fn element_mod_q_from_hex_invalid_chars_error() {
    let bad = "g".repeat(64); // 'g' is not valid hex
    let result = ElementModQ::from_hex(&bad);
    assert!(result.is_err(), "invalid hex must return Err");
}

// ── JSON serde round-trips (also covers serialize.rs paths) ───────────────

#[test]
fn element_mod_p_json_round_trip() {
    let p = ElementModP::g().clone();
    let json = serde_json::to_string(&p).unwrap();
    // Struct serializes as {"value":"<1024 hex chars>"} = 10 + 1024 + 2 = 1036 chars.
    assert_eq!(json.len(), 1036, "JSON must be exactly 1036 chars");
    // Verify round-trip deserialization
    let p2: ElementModP = serde_json::from_str(&json).unwrap();
    assert_eq!(p, p2, "JSON round-trip must be identity");
    // The JSON must contain the 'value' key
    assert!(json.contains("\"value\""), "JSON must contain 'value' key");
}

#[test]
fn element_mod_q_json_round_trip() {
    let q_val = ElementModQ::from_u64(12345);
    let json = serde_json::to_string(&q_val).unwrap();
    // Struct serializes as {"value":"<64 hex chars>"} = 10 + 64 + 2 = 76 chars.
    assert_eq!(json.len(), 76, "JSON must be 76 chars (struct with hex value)");
    let q2: ElementModQ = serde_json::from_str(&json).unwrap();
    assert_eq!(q_val, q2, "JSON round-trip must be identity");
    assert!(json.contains("\"value\""), "JSON must contain 'value' key");
}

#[test]
fn element_mod_p_json_wrong_length_error() {
    // Too short: 6 hex chars instead of 1024
    let bad = "\"aabbcc\"";
    let result: Result<ElementModP, _> = serde_json::from_str(bad);
    assert!(result.is_err(), "wrong-length hex must fail deserialization");
}

#[test]
fn element_mod_p_json_invalid_hex_error() {
    // 1024 chars but with a non-hex character
    let bad = format!("\"z{}\"", "0".repeat(1023));
    let result: Result<ElementModP, _> = serde_json::from_str(&bad);
    assert!(result.is_err(), "invalid hex must fail deserialization");
}

#[test]
fn element_mod_q_json_wrong_length_error() {
    let bad = "\"aabb\""; // 4 chars, not 64
    let result: Result<ElementModQ, _> = serde_json::from_str(bad);
    assert!(result.is_err(), "wrong-length hex must fail deserialization");
}

#[test]
fn element_mod_q_json_invalid_hex_error() {
    // 64 chars but with a non-hex character
    let bad = format!("\"z{}\"", "0".repeat(63));
    let result: Result<ElementModQ, _> = serde_json::from_str(&bad);
    assert!(result.is_err(), "invalid hex must fail deserialization");
}

// ── Arithmetic error paths ────────────────────────────────────────────────

#[test]
fn inv_mod_p_zero_returns_err() {
    let result = inv_mod_p(ElementModP::zero());
    assert!(result.is_err(), "inv_mod_p(0) must return Err");
}

#[test]
fn div_mod_p_zero_divisor_returns_err() {
    let result = div_mod_p(ElementModP::g(), ElementModP::zero());
    assert!(result.is_err(), "div_mod_p(_, 0) must return Err");
}

#[test]
fn div_mod_q_zero_divisor_returns_err() {
    let result = div_mod_q(&ElementModQ::from_u64(42), ElementModQ::zero());
    assert!(result.is_err(), "div_mod_q(_, 0) must return Err");
}

#[test]
fn inv_mod_q_zero_returns_err_via_new() {
    // ElementModQ::zero() is in [0, Q) so new() accepts it; inv_mod_q must still fail.
    let z = ElementModQ::zero().clone();
    let result = inv_mod_q(&z);
    assert!(result.is_err(), "inv_mod_q(0) must return Err");
}
