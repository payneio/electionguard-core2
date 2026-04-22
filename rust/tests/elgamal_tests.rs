//! Integration tests for ElGamal encryption.
//!
//! Tests: encrypt/decrypt round-trip (via re-encryption), homomorphic property,
//! HashedElGamal encrypt/decrypt round-trip, and nonce diversity.

use electionguard_core2::{
    elgamal::{
        ElGamalCiphertext, ElGamalKeyPair,
        elgamal_encrypt, elgamal_add, elgamal_accumulate,
        hashed_elgamal_encrypt, hashed_elgamal_decrypt,
        encrypt_ballot_nonce, verify_ballot_nonce,
        HashedElGamalCiphertext,
    },
    group::{
        ElementModQ,
        g_pow, pow_mod_p, mul_mod_p, add_mod_q,
    },
};

// ── Basic encrypt sanity ──────────────────────────────────────────────────────

/// `pad = g^nonce` and `data = g^plaintext * public_key^nonce`.
#[test]
fn elgamal_encrypt_components() {
    let secret = ElementModQ::from_u64(42);
    let kp = ElGamalKeyPair::from_secret(secret);
    let nonce = ElementModQ::from_u64(7);

    let ct = elgamal_encrypt(1, &nonce, &kp.public_key);

    // pad = g^7
    let expected_pad = g_pow(&nonce);
    assert_eq!(ct.pad, expected_pad, "pad should be g^nonce");

    // data = g^1 * K^7
    let g1 = g_pow(&ElementModQ::from_u64(1));
    let k7 = pow_mod_p(&kp.public_key, &nonce);
    let expected_data = mul_mod_p(&g1, &k7);
    assert_eq!(ct.data, expected_data, "data should be g^plaintext * K^nonce");
}

/// Encrypting 0 gives `data = K^nonce` (no g factor).
#[test]
fn elgamal_encrypt_zero_has_no_g_factor() {
    let secret = ElementModQ::from_u64(99);
    let kp = ElGamalKeyPair::from_secret(secret);
    let nonce = ElementModQ::from_u64(3);

    let ct = elgamal_encrypt(0, &nonce, &kp.public_key);

    // data should equal K^nonce (since g^0 = 1)
    let expected_data = pow_mod_p(&kp.public_key, &nonce);
    assert_eq!(ct.data, expected_data, "encrypting 0: data = K^nonce");
}

// ── Determinism ───────────────────────────────────────────────────────────────

/// Same inputs → same ciphertext.
#[test]
fn elgamal_encrypt_is_deterministic() {
    let sk = ElementModQ::from_u64(55);
    let kp = ElGamalKeyPair::from_secret(sk);
    let nonce = ElementModQ::from_u64(13);

    let ct1 = elgamal_encrypt(1, &nonce, &kp.public_key);
    let ct2 = elgamal_encrypt(1, &nonce, &kp.public_key);
    assert_eq!(ct1, ct2, "same inputs must produce identical ciphertexts");
}

/// Different nonces → different pads (and almost certainly different data).
#[test]
fn different_nonces_produce_different_ciphertexts() {
    let sk = ElementModQ::from_u64(33);
    let kp = ElGamalKeyPair::from_secret(sk);
    let n1 = ElementModQ::from_u64(5);
    let n2 = ElementModQ::from_u64(6);

    let ct1 = elgamal_encrypt(1, &n1, &kp.public_key);
    let ct2 = elgamal_encrypt(1, &n2, &kp.public_key);

    assert_ne!(ct1.pad,  ct2.pad,  "different nonces → different pads");
    assert_ne!(ct1.data, ct2.data, "different nonces → different data");
}

// ── Homomorphic addition ──────────────────────────────────────────────────────

/// `enc(0) + enc(1) = enc(1)` in the homomorphic sense:
/// `pad₁·pad₂ = g^(n1+n2)`.
#[test]
fn elgamal_add_pads_multiply() {
    let sk = ElementModQ::from_u64(77);
    let kp = ElGamalKeyPair::from_secret(sk);
    let n1 = ElementModQ::from_u64(3);
    let n2 = ElementModQ::from_u64(5);

    let ct0 = elgamal_encrypt(0, &n1, &kp.public_key);
    let ct1 = elgamal_encrypt(1, &n2, &kp.public_key);

    let sum = elgamal_add(&ct0, &ct1);
    let n12 = add_mod_q(&n1, &n2);
    let expected_pad = g_pow(&n12);
    assert_eq!(sum.pad, expected_pad, "homomorphic add: pad = g^(n1+n2)");
}

/// `enc(a) + enc(b) data` = `g^(a+b) * K^(n1+n2)`.
#[test]
fn elgamal_add_data_component() {
    let sk = ElementModQ::from_u64(77);
    let kp = ElGamalKeyPair::from_secret(sk);
    let n1 = ElementModQ::from_u64(3);
    let n2 = ElementModQ::from_u64(5);

    let ct1 = elgamal_encrypt(1, &n1, &kp.public_key);
    let ct2 = elgamal_encrypt(1, &n2, &kp.public_key);
    let sum = elgamal_add(&ct1, &ct2);

    // Expected data = g^2 * K^(n1+n2)
    let g2 = g_pow(&ElementModQ::from_u64(2));
    let n12 = add_mod_q(&n1, &n2);
    let kn12 = pow_mod_p(&kp.public_key, &n12);
    let expected_data = mul_mod_p(&g2, &kn12);
    assert_eq!(sum.data, expected_data, "homomorphic add: data = g^2 * K^(n1+n2)");
}

/// Accumulate is consistent with repeated add.
#[test]
fn elgamal_accumulate_matches_repeated_add() {
    let sk = ElementModQ::from_u64(17);
    let kp = ElGamalKeyPair::from_secret(sk);

    let cts: Vec<ElGamalCiphertext> = (1u64..=4).map(|i| {
        elgamal_encrypt(i % 2, &ElementModQ::from_u64(i * 3), &kp.public_key)
    }).collect();

    let refs: Vec<&ElGamalCiphertext> = cts.iter().collect();
    let by_accumulate = elgamal_accumulate(&refs);

    let mut by_add = cts[0].clone();
    for ct in &cts[1..] {
        by_add = elgamal_add(&by_add, ct);
    }

    assert_eq!(by_accumulate, by_add, "accumulate should match repeated add");
}

/// Accumulate of empty slice = identity ciphertext (1, 1).
#[test]
fn elgamal_accumulate_empty_is_identity() {
    let acc = elgamal_accumulate(&[]);
    assert!(acc.pad.is_one(),  "empty accumulate pad should be 1");
    assert!(acc.data.is_one(), "empty accumulate data should be 1");
}

// ── HashedElGamal encrypt/decrypt ─────────────────────────────────────────────

fn make_hashed_context() -> (ElGamalKeyPair, ElementModQ, ElementModQ) {
    let kp = ElGamalKeyPair::from_secret(ElementModQ::from_u64(0xDEAD_BEEF));
    let sel_id = ElementModQ::from_u64(0xABCD_1234);
    let nonce = ElementModQ::from_u64(0x5678_9ABC);
    (kp, sel_id, nonce)
}

/// Encrypt then decrypt round-trip for hashed ElGamal.
#[test]
fn hashed_elgamal_round_trip() {
    let (kp, sel_id, nonce) = make_hashed_context();
    let plaintext = b"Hello, ElectionGuard!";

    let ct = hashed_elgamal_encrypt(plaintext, &nonce, &kp.public_key, &sel_id, 1, false)
        .expect("encrypt failed");

    let recovered = hashed_elgamal_decrypt(&ct, &kp.secret_key, &sel_id, 1)
        .expect("decrypt failed");

    assert_eq!(&recovered[..], plaintext, "decrypted text must match original");
}

/// Round-trip for empty message.
#[test]
fn hashed_elgamal_empty_message() {
    let (kp, sel_id, nonce) = make_hashed_context();

    let ct = hashed_elgamal_encrypt(b"", &nonce, &kp.public_key, &sel_id, 1, false)
        .expect("encrypt empty failed");
    let recovered = hashed_elgamal_decrypt(&ct, &kp.secret_key, &sel_id, 1)
        .expect("decrypt empty failed");

    assert!(recovered.is_empty(), "decrypted empty should be empty");
}

/// Wrong contest index → different keys → MAC failure.
#[test]
fn hashed_elgamal_wrong_contest_index_fails() {
    let (kp, sel_id, nonce) = make_hashed_context();
    let plaintext = b"secret";

    let ct = hashed_elgamal_encrypt(plaintext, &nonce, &kp.public_key, &sel_id, 1, false)
        .expect("encrypt failed");

    // Decrypting with contest_index=2 uses a different KDF context → different key
    let result = hashed_elgamal_decrypt(&ct, &kp.secret_key, &sel_id, 2);
    assert!(result.is_err(), "wrong contest index should fail MAC verification");
}

/// Different nonces produce different ciphertexts.
#[test]
fn hashed_elgamal_different_nonces_differ() {
    let (kp, sel_id, _) = make_hashed_context();
    let plaintext = b"test";

    let n1 = ElementModQ::from_u64(1);
    let n2 = ElementModQ::from_u64(2);

    let ct1 = hashed_elgamal_encrypt(plaintext, &n1, &kp.public_key, &sel_id, 1, false).unwrap();
    let ct2 = hashed_elgamal_encrypt(plaintext, &n2, &kp.public_key, &sel_id, 1, false).unwrap();

    assert_ne!(ct1.pad,  ct2.pad,  "different nonces → different pads");
    assert_ne!(ct1.data, ct2.data, "different nonces → different ciphertexts");
}

// ── Ballot nonce encryption ───────────────────────────────────────────────────

/// Encrypt ballot nonce produces a structurally valid ciphertext.
#[test]
fn encrypt_ballot_nonce_produces_valid_ciphertext() {
    let kp = ElGamalKeyPair::from_secret(ElementModQ::from_u64(123));
    let ballot_nonce = ElementModQ::from_u64(456);
    let nonce = ElementModQ::from_u64(789);
    let sel_id = ElementModQ::from_u64(101112);

    let ct = encrypt_ballot_nonce(&ballot_nonce, &nonce, &kp.public_key, &sel_id)
        .expect("encrypt_ballot_nonce failed");

    // Must pass structural verification.
    let ok = verify_ballot_nonce(&ct, &kp.public_key, &sel_id)
        .expect("verify_ballot_nonce failed");
    assert!(ok, "encrypted ballot nonce should be structurally valid");

    // Data must be exactly 32 bytes (one ElementModQ).
    assert_eq!(ct.data.len(), 32, "ballot nonce data should be 32 bytes");
    // MAC must be 32 bytes.
    assert_eq!(ct.mac.len(), 32, "ballot nonce MAC should be 32 bytes");
}

/// Ballot nonce cipher with truncated data fails verify.
#[test]
fn verify_ballot_nonce_bad_data_length_fails() {
    let kp = ElGamalKeyPair::from_secret(ElementModQ::from_u64(1));
    let sel_id = ElementModQ::from_u64(2);
    let bad_ct = HashedElGamalCiphertext {
        pad: g_pow(&ElementModQ::from_u64(3)),
        data: vec![0u8; 16], // too short
        mac: vec![0u8; 32],
    };
    let ok = verify_ballot_nonce(&bad_ct, &kp.public_key, &sel_id).unwrap();
    assert!(!ok, "short data should fail ballot nonce verification");
}

// ── Key pair ──────────────────────────────────────────────────────────────────

/// `public_key = g^secret_key`.
#[test]
fn key_pair_public_key_is_g_pow_secret() {
    let sk = ElementModQ::from_u64(12345);
    let kp = ElGamalKeyPair::from_secret(sk.clone());
    let expected_pk = g_pow(&sk);
    assert_eq!(kp.public_key, expected_pk);
}

// ── ElGamalKeyPair::generate (lines 40-42 in elgamal.rs) ─────────────────

#[test]
fn key_pair_generate_with_rng() {
    let mut rng = rand::thread_rng();
    let kp = ElGamalKeyPair::generate(&mut rng);
    // public_key must equal g^secret_key
    let expected = g_pow(&kp.secret_key);
    assert_eq!(kp.public_key, expected);
}

#[test]
fn key_pair_generate_produces_distinct_keys() {
    let mut rng = rand::thread_rng();
    let kp1 = ElGamalKeyPair::generate(&mut rng);
    let kp2 = ElGamalKeyPair::generate(&mut rng);
    assert_ne!(kp1.public_key, kp2.public_key, "two generated keys should differ");
}

// ── xor_keystream non-empty message path (line 171 in elgamal.rs) ─────────

#[test]
fn hashed_elgamal_encrypt_decrypt_non_empty_message() {
    let sk = ElementModQ::from_u64(17);
    let kp = ElGamalKeyPair::from_secret(sk);
    let nonce = ElementModQ::from_u64(99);
    let sel_id = ElementModQ::from_u64(3);
    let message = b"hello world!";

    let ct = hashed_elgamal_encrypt(message, &nonce, &kp.public_key, &sel_id, 1, false).unwrap();
    let plaintext = hashed_elgamal_decrypt(&ct, &kp.secret_key, &sel_id, 1).unwrap();
    assert_eq!(plaintext, message, "hashed ElGamal round-trip must recover plaintext");
}

// ── should_verify = true path (lines 224-226 in elgamal.rs) ──────────────

#[test]
fn hashed_elgamal_encrypt_with_verify_flag() {
    let sk = ElementModQ::from_u64(23);
    let kp = ElGamalKeyPair::from_secret(sk);
    let nonce = ElementModQ::from_u64(7);
    let sel_id = ElementModQ::from_u64(5);
    let message = b"verify me";

    // should_verify = true must not panic or error for a correct encryption
    let ct =
        hashed_elgamal_encrypt(message, &nonce, &kp.public_key, &sel_id, 1, true).unwrap();
    let plaintext = hashed_elgamal_decrypt(&ct, &kp.secret_key, &sel_id, 1).unwrap();
    assert_eq!(plaintext, message);
}

// ── verify_ballot_nonce success path (line 327 in elgamal.rs) ────────────

#[test]
fn verify_ballot_nonce_valid_ciphertext_returns_true() {
    let ballot_nonce = ElementModQ::from_u64(55);
    let encryption_nonce = ElementModQ::from_u64(66);
    let sk = ElementModQ::from_u64(77);
    let kp = ElGamalKeyPair::from_secret(sk);
    let sel_id = ElementModQ::from_u64(88);

    let ct = encrypt_ballot_nonce(&ballot_nonce, &encryption_nonce, &kp.public_key, &sel_id)
        .unwrap();
    // Structural verification should succeed
    let ok = verify_ballot_nonce(&ct, &kp.public_key, &sel_id).unwrap();
    assert!(ok, "valid ballot nonce ciphertext must pass verification");
}
