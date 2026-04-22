//! Integration tests for zero-knowledge proof types.
//!
//! Tests: disjunctive, constant, ranged, and unified range proofs —
//! valid generation, verification, and rejection of corrupt proofs.

use electionguard_core2::{
    elgamal::{elgamal_encrypt, elgamal_accumulate},
    group::{
        ElementModP, ElementModQ,
        g_pow, add_mod_q,
    },
    proof::{
        ChaumPedersenProof,
        DisjunctiveChaumPedersenProof,
        ConstantChaumPedersenProof,
        RangedChaumPedersenProof,
        UnifiedRangeProof,
    },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_keypair(secret: u64) -> (ElementModQ, ElementModP) {
    let sk = ElementModQ::from_u64(secret);
    let pk = g_pow(&sk);
    (sk, pk)
}

fn sel_id(v: u64) -> ElementModQ {
    ElementModQ::from_u64(v)
}

fn seed(v: u64) -> ElementModQ {
    ElementModQ::from_u64(v)
}

// ── ChaumPedersenProof (base) ─────────────────────────────────────────────────

#[test]
fn chaum_pedersen_struct_accessible() {
    let q = ElementModQ::from_u64(42);
    let p = g_pow(&q);
    let proof = ChaumPedersenProof::new(p.clone(), p.clone(), q.clone(), q.clone());
    assert_eq!(proof.challenge, q);
    assert_eq!(proof.response, q);
    assert_eq!(proof.pad, p);
    assert_eq!(proof.data, p);
}

// ── DisjunctiveChaumPedersenProof ─────────────────────────────────────────────

#[test]
fn disjunctive_proof_zero_verifies() {
    let (_, pk) = make_keypair(11);
    let nonce = ElementModQ::from_u64(17);
    let ct = elgamal_encrypt(0, &nonce, &pk);

    let proof = DisjunctiveChaumPedersenProof::make(
        &ct, 0, &nonce, &pk, &seed(100), &sel_id(200),
    ).expect("make proof_zero failed");

    assert!(proof.verify(&ct, &pk, &sel_id(200)),
        "disjunctive proof for 0 must verify");
}

#[test]
fn disjunctive_proof_one_verifies() {
    let (_, pk) = make_keypair(11);
    let nonce = ElementModQ::from_u64(19);
    let ct = elgamal_encrypt(1, &nonce, &pk);

    let proof = DisjunctiveChaumPedersenProof::make(
        &ct, 1, &nonce, &pk, &seed(300), &sel_id(400),
    ).expect("make proof_one failed");

    assert!(proof.verify(&ct, &pk, &sel_id(400)),
        "disjunctive proof for 1 must verify");
}

/// A valid disjunctive proof must also pass when extended_hash == selection_enc_id.
#[test]
fn disjunctive_proof_same_hash_both_ways() {
    let (_, pk) = make_keypair(7);
    let nonce = ElementModQ::from_u64(5);
    let ct = elgamal_encrypt(1, &nonce, &pk);
    let hash = sel_id(999);

    let proof = DisjunctiveChaumPedersenProof::make(
        &ct, 1, &nonce, &pk, &seed(111), &hash,
    ).unwrap();

    assert!(proof.verify(&ct, &pk, &hash));
}

/// Wrong hash in verify → challenge mismatch → fail.
#[test]
fn disjunctive_proof_wrong_hash_fails() {
    let (_, pk) = make_keypair(33);
    let nonce = ElementModQ::from_u64(44);
    let ct = elgamal_encrypt(0, &nonce, &pk);

    let proof = DisjunctiveChaumPedersenProof::make(
        &ct, 0, &nonce, &pk, &seed(1), &sel_id(2),
    ).unwrap();

    assert!(!proof.verify(&ct, &pk, &sel_id(9999)),
        "wrong hash must fail verification");
}

/// Tampered challenge → fails.
#[test]
fn disjunctive_proof_tampered_challenge_fails() {
    let (_, pk) = make_keypair(13);
    let nonce = ElementModQ::from_u64(31);
    let ct = elgamal_encrypt(1, &nonce, &pk);
    let hash = sel_id(42);

    let mut proof = DisjunctiveChaumPedersenProof::make(
        &ct, 1, &nonce, &pk, &seed(77), &hash,
    ).unwrap();

    // Tamper with the challenge
    proof.challenge = ElementModQ::from_u64(0xDEAD);

    assert!(!proof.verify(&ct, &pk, &hash),
        "tampered challenge must fail");
}

/// Plaintext=2 must be rejected immediately.
#[test]
fn disjunctive_proof_invalid_plaintext_errors() {
    let (_, pk) = make_keypair(5);
    let nonce = ElementModQ::from_u64(3);
    let ct = elgamal_encrypt(0, &nonce, &pk);

    let result = DisjunctiveChaumPedersenProof::make(
        &ct, 2, &nonce, &pk, &seed(1), &sel_id(1),
    );
    assert!(result.is_err(), "plaintext=2 must be an error");
}

// ── ConstantChaumPedersenProof ─────────────────────────────────────────────────

fn make_constant_context(plaintexts: &[u64]) -> (
    electionguard_core2::elgamal::ElGamalCiphertext,
    ElementModQ, // accumulated nonce
    ElementModP, // public key
) {
    let (_, pk) = make_keypair(7919);

    let nonces: Vec<ElementModQ> = plaintexts.iter().enumerate()
        .map(|(i, _)| ElementModQ::from_u64((i as u64 + 1) * 37))
        .collect();

    let cts: Vec<_> = plaintexts.iter().zip(nonces.iter())
        .map(|(p, n)| elgamal_encrypt(*p, n, &pk))
        .collect();

    let refs: Vec<&_> = cts.iter().collect();
    let acc = elgamal_accumulate(&refs);

    let mut nonce_sum = ElementModQ::from_u64(0);
    for n in &nonces {
        nonce_sum = add_mod_q(&nonce_sum, n);
    }

    (acc, nonce_sum, pk)
}

#[test]
fn constant_proof_single_selection_1() {
    let (acc, nonce, pk) = make_constant_context(&[1]);
    let proof = ConstantChaumPedersenProof::make(
        &acc, 1, &nonce, &pk, &seed(5), &sel_id(6),
    ).expect("make constant proof failed");

    assert!(proof.verify(&acc, &pk, &sel_id(6)),
        "constant proof for S=1 must verify");
}

#[test]
fn constant_proof_two_selections_sum_1() {
    let (acc, nonce, pk) = make_constant_context(&[1, 0]);
    let proof = ConstantChaumPedersenProof::make(
        &acc, 1, &nonce, &pk, &seed(10), &sel_id(20),
    ).expect("make constant proof failed");

    assert!(proof.verify(&acc, &pk, &sel_id(20)),
        "constant proof for S=1 (two selections) must verify");
}

#[test]
fn constant_proof_sum_2() {
    let (acc, nonce, pk) = make_constant_context(&[1, 1]);
    let proof = ConstantChaumPedersenProof::make(
        &acc, 2, &nonce, &pk, &seed(50), &sel_id(60),
    ).expect("make constant proof S=2 failed");

    assert!(proof.verify(&acc, &pk, &sel_id(60)),
        "constant proof for S=2 must verify");
}

#[test]
fn constant_proof_wrong_constant_fails() {
    let (acc, nonce, pk) = make_constant_context(&[1, 0]);

    let proof = ConstantChaumPedersenProof::make(
        &acc, 1, &nonce, &pk, &seed(7), &sel_id(8),
    ).unwrap();

    // Tamper: claim constant=2 instead of 1
    let mut bad = proof.clone();
    bad.constant = 2;
    assert!(!bad.verify(&acc, &pk, &sel_id(8)),
        "wrong constant must fail verification");
}

#[test]
fn constant_proof_wrong_hash_fails() {
    let (acc, nonce, pk) = make_constant_context(&[1]);
    let proof = ConstantChaumPedersenProof::make(
        &acc, 1, &nonce, &pk, &seed(3), &sel_id(4),
    ).unwrap();

    assert!(!proof.verify(&acc, &pk, &sel_id(9999)),
        "wrong extended_hash must fail constant proof");
}

// ── RangedChaumPedersenProof ──────────────────────────────────────────────────

#[test]
fn ranged_proof_plaintext_0_limit_1() {
    let (_, pk) = make_keypair(101);
    let nonce = ElementModQ::from_u64(202);
    let ct = elgamal_encrypt(0, &nonce, &pk);

    let proof = RangedChaumPedersenProof::make(
        &ct, 0, &nonce, &pk, &seed(303), 1, &sel_id(404),
    ).expect("make ranged 0/1 failed");

    assert!(proof.verify(&ct, &pk, &sel_id(404)),
        "ranged proof for 0 in [0,1] must verify");
}

#[test]
fn ranged_proof_plaintext_1_limit_1() {
    let (_, pk) = make_keypair(101);
    let nonce = ElementModQ::from_u64(202);
    let ct = elgamal_encrypt(1, &nonce, &pk);

    let proof = RangedChaumPedersenProof::make(
        &ct, 1, &nonce, &pk, &seed(500), 1, &sel_id(600),
    ).expect("make ranged 1/1 failed");

    assert!(proof.verify(&ct, &pk, &sel_id(600)),
        "ranged proof for 1 in [0,1] must verify");
}

#[test]
fn ranged_proof_larger_range() {
    let (_, pk) = make_keypair(41);
    let nonce = ElementModQ::from_u64(43);
    let ct = elgamal_encrypt(3, &nonce, &pk);

    let proof = RangedChaumPedersenProof::make(
        &ct, 3, &nonce, &pk, &seed(777), 5, &sel_id(888),
    ).expect("make ranged 3/5 failed");

    assert!(proof.verify(&ct, &pk, &sel_id(888)),
        "ranged proof for 3 in [0,5] must verify");
}

#[test]
fn ranged_proof_at_limit() {
    let (_, pk) = make_keypair(61);
    let nonce = ElementModQ::from_u64(71);
    let ct = elgamal_encrypt(4, &nonce, &pk);

    let proof = RangedChaumPedersenProof::make(
        &ct, 4, &nonce, &pk, &seed(81), 4, &sel_id(91),
    ).expect("make ranged at limit failed");

    assert!(proof.verify(&ct, &pk, &sel_id(91)),
        "ranged proof at limit must verify");
}

#[test]
fn ranged_proof_out_of_range_errors() {
    let (_, pk) = make_keypair(101);
    let nonce = ElementModQ::from_u64(202);
    let ct = elgamal_encrypt(0, &nonce, &pk);

    let result = RangedChaumPedersenProof::make(
        &ct, 5, &nonce, &pk, &seed(10), 4, &sel_id(11),
    );
    assert!(result.is_err(), "plaintext > range_limit should error");
}

#[test]
fn ranged_proof_wrong_hash_fails() {
    let (_, pk) = make_keypair(17);
    let nonce = ElementModQ::from_u64(23);
    let ct = elgamal_encrypt(1, &nonce, &pk);

    let proof = RangedChaumPedersenProof::make(
        &ct, 1, &nonce, &pk, &seed(1), 2, &sel_id(2),
    ).unwrap();

    assert!(!proof.verify(&ct, &pk, &sel_id(9999)),
        "wrong hash must fail ranged proof");
}

// ── UnifiedRangeProof ─────────────────────────────────────────────────────────

#[test]
fn unified_range_one_bit_zero() {
    let (_, pk) = make_keypair(1000);
    let nonce = ElementModQ::from_u64(2000);
    let ct = elgamal_encrypt(0, &nonce, &pk);

    let proof = UnifiedRangeProof::make(
        &ct, 0, &nonce, &pk, &sel_id(3000), 1,
    ).expect("make unified 1-bit/0 failed");

    assert!(proof.verify(&ct, &pk, &sel_id(3000), 1),
        "unified proof 1-bit plaintext=0 must verify");
}

#[test]
fn unified_range_one_bit_one() {
    let (_, pk) = make_keypair(1001);
    let nonce = ElementModQ::from_u64(2001);
    let ct = elgamal_encrypt(1, &nonce, &pk);

    let proof = UnifiedRangeProof::make(
        &ct, 1, &nonce, &pk, &sel_id(3001), 1,
    ).expect("make unified 1-bit/1 failed");

    assert!(proof.verify(&ct, &pk, &sel_id(3001), 1),
        "unified proof 1-bit plaintext=1 must verify");
}

#[test]
fn unified_range_four_bits() {
    let (_, pk) = make_keypair(5000);
    let nonce = ElementModQ::from_u64(6000);
    let ct = elgamal_encrypt(9, &nonce, &pk);

    let proof = UnifiedRangeProof::make(
        &ct, 9, &nonce, &pk, &sel_id(7000), 4,
    ).expect("make unified 4-bit/9 failed");

    assert!(proof.verify(&ct, &pk, &sel_id(7000), 4),
        "unified proof 4-bit plaintext=9 must verify");
}

#[test]
fn unified_range_out_of_range_errors() {
    let (_, pk) = make_keypair(9);
    let nonce = ElementModQ::from_u64(11);
    let ct = elgamal_encrypt(0, &nonce, &pk);

    // 16 >= 2^4
    let result = UnifiedRangeProof::make(
        &ct, 16, &nonce, &pk, &sel_id(1), 4,
    );
    assert!(result.is_err(), "unified: plaintext=16 for 4 bits should error");
}

#[test]
fn unified_range_wrong_hash_fails() {
    let (_, pk) = make_keypair(123);
    let nonce = ElementModQ::from_u64(456);
    let ct = elgamal_encrypt(3, &nonce, &pk);

    let proof = UnifiedRangeProof::make(
        &ct, 3, &nonce, &pk, &sel_id(789), 4,
    ).unwrap();

    // Wrong sel_id in verify
    assert!(!proof.verify(&ct, &pk, &sel_id(9999), 4),
        "wrong hash must fail unified range proof");
}

#[test]
fn unified_range_wrong_range_bits_fails() {
    let (_, pk) = make_keypair(77);
    let nonce = ElementModQ::from_u64(88);
    let ct = elgamal_encrypt(1, &nonce, &pk);

    let proof = UnifiedRangeProof::make(
        &ct, 1, &nonce, &pk, &sel_id(99), 2,
    ).unwrap();

    // Verifying with different range_bits → commitments.len() mismatch
    assert!(!proof.verify(&ct, &pk, &sel_id(99), 4),
        "wrong range_bits must fail unified range proof");
}

// ── Serialization round-trips ─────────────────────────────────────────────────

#[test]
fn disjunctive_proof_serde_roundtrip() {
    let (_, pk) = make_keypair(555);
    let nonce = ElementModQ::from_u64(666);
    let ct = elgamal_encrypt(1, &nonce, &pk);
    let hash = sel_id(777);

    let proof = DisjunctiveChaumPedersenProof::make(
        &ct, 1, &nonce, &pk, &seed(888), &hash,
    ).unwrap();

    let json = serde_json::to_string(&proof).expect("serialize failed");
    let proof2: DisjunctiveChaumPedersenProof =
        serde_json::from_str(&json).expect("deserialize failed");

    assert!(proof2.verify(&ct, &pk, &hash),
        "deserialized disjunctive proof must still verify");
}

#[test]
fn constant_proof_serde_roundtrip() {
    let (acc, nonce, pk) = make_constant_context(&[1, 0]);
    let hash = sel_id(1234);

    let proof = ConstantChaumPedersenProof::make(
        &acc, 1, &nonce, &pk, &seed(5678), &hash,
    ).unwrap();

    let json = serde_json::to_string(&proof).expect("serialize failed");
    let proof2: ConstantChaumPedersenProof =
        serde_json::from_str(&json).expect("deserialize failed");

    assert!(proof2.verify(&acc, &pk, &hash),
        "deserialized constant proof must still verify");
}

#[test]
fn ranged_proof_serde_roundtrip() {
    let (_, pk) = make_keypair(333);
    let nonce = ElementModQ::from_u64(444);
    let ct = elgamal_encrypt(2, &nonce, &pk);
    let hash = sel_id(555);

    let proof = RangedChaumPedersenProof::make(
        &ct, 2, &nonce, &pk, &seed(666), 3, &hash,
    ).unwrap();

    let json = serde_json::to_string(&proof).expect("serialize failed");
    let proof2: RangedChaumPedersenProof =
        serde_json::from_str(&json).expect("deserialize failed");

    assert!(proof2.verify(&ct, &pk, &hash),
        "deserialized ranged proof must still verify");
}

#[test]
fn unified_range_proof_serde_roundtrip() {
    let (_, pk) = make_keypair(11);
    let nonce = ElementModQ::from_u64(22);
    let ct = elgamal_encrypt(3, &nonce, &pk);
    let hash = sel_id(33);

    let proof = UnifiedRangeProof::make(
        &ct, 3, &nonce, &pk, &hash, 3,
    ).unwrap();

    let json = serde_json::to_string(&proof).expect("serialize failed");
    let proof2: UnifiedRangeProof =
        serde_json::from_str(&json).expect("deserialize failed");

    assert!(proof2.verify(&ct, &pk, &hash, 3),
        "deserialized unified range proof must still verify");
}
