//! Tests for the hash, HMAC, KDF, and nonces modules.

use electionguard_core2::{
    ElementModQ,
    hash_elems_v21, hash_elems_v21_q, hash_elems_v21_raw,
    HashableValue,
    hmac_sha256, hmac_sha256_verify,
    kdf_hmac_sha256, kdf_key,
    compute_selection_encryption_id, derive_selection_nonce, derive_contest_data_nonce,
};
use electionguard_core2::group::constants::Q_VALUE;
use electionguard_core2::nonces::Nonces;

// ── HMAC-SHA-256 ──────────────────────────────────────────────────────────────

#[test]
fn hmac_sha256_deterministic() {
    let key = b"test-key-32bytes-exactly-padded!!";
    let msg = b"hello world";
    let h1 = hmac_sha256(key, msg);
    let h2 = hmac_sha256(key, msg);
    assert_eq!(h1, h2);
}

#[test]
fn hmac_sha256_different_key_different_output() {
    let msg = b"hello world";
    let h1 = hmac_sha256(b"key-one", msg);
    let h2 = hmac_sha256(b"key-two", msg);
    assert_ne!(h1, h2);
}

#[test]
fn hmac_sha256_different_message_different_output() {
    let key = b"key";
    let h1 = hmac_sha256(key, b"message1");
    let h2 = hmac_sha256(key, b"message2");
    assert_ne!(h1, h2);
}

#[test]
fn hmac_verify_correct() {
    let key = b"secret";
    let msg = b"payload";
    let tag = hmac_sha256(key, msg);
    assert!(hmac_sha256_verify(key, msg, &tag));
}

#[test]
fn hmac_verify_tampered_message() {
    let key = b"secret";
    let tag = hmac_sha256(key, b"original");
    assert!(!hmac_sha256_verify(key, b"tampered", &tag));
}

#[test]
fn hmac_verify_tampered_tag() {
    let key = b"secret";
    let msg = b"payload";
    let mut tag = hmac_sha256(key, msg);
    tag[0] ^= 0xFF; // flip a bit
    assert!(!hmac_sha256_verify(key, msg, &tag));
}

/// RFC 4231 test case 1.
#[test]
fn hmac_sha256_rfc4231_case1() {
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let expected =
        hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
            .unwrap();
    let result = hmac_sha256(&key, data);
    assert_eq!(&result[..], &expected[..]);
}

/// RFC 4231 test case 2 (key shorter than block).
#[test]
fn hmac_sha256_rfc4231_case2() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected =
        hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
            .unwrap();
    let result = hmac_sha256(key, data);
    assert_eq!(&result[..], &expected[..]);
}

// ── KDF ───────────────────────────────────────────────────────────────────────

#[test]
fn kdf_deterministic() {
    let k = [0u8; 32];
    let a = kdf_hmac_sha256(&k, b"label", b"ctx", 64);
    let b = kdf_hmac_sha256(&k, b"label", b"ctx", 64);
    assert_eq!(a, b);
}

#[test]
fn kdf_different_label_different_output() {
    let k = [0u8; 32];
    let a = kdf_hmac_sha256(&k, b"label-A", b"", 32);
    let b = kdf_hmac_sha256(&k, b"label-B", b"", 32);
    assert_ne!(a, b);
}

#[test]
fn kdf_different_context_different_output() {
    let k = [0u8; 32];
    let a = kdf_hmac_sha256(&k, b"label", b"ctx-A", 32);
    let b = kdf_hmac_sha256(&k, b"label", b"ctx-B", 32);
    assert_ne!(a, b);
}

#[test]
fn kdf_output_length_matches_request() {
    let k = [0u8; 32];
    for len in [1, 16, 32, 33, 64, 128] {
        let out = kdf_hmac_sha256(&k, b"test", b"", len);
        assert_eq!(out.len(), len, "KDF must produce exactly {len} bytes");
    }
}

#[test]
fn kdf_key_matches_first_32_bytes_of_kdf() {
    let k = [0xABu8; 32];
    let vec_out = kdf_hmac_sha256(&k, b"key", b"ctx", 32);
    let arr_out = kdf_key(&k, b"key", b"ctx");
    assert_eq!(&vec_out[..], &arr_out[..]);
}

#[test]
fn kdf_first_block_is_hmac_of_counter_1() {
    // Manually compute the first KDF block and verify it matches HMAC(k, 1||label||0||ctx)
    let k = [0u8; 32];
    let label = b"test";
    let ctx = b"";

    // SP 800-108r1 counter mode: PRF(k, counter || label || 0x00 || context)
    let mut prf_input = Vec::new();
    prf_input.extend_from_slice(&1u32.to_be_bytes()); // counter = 1 BE
    prf_input.extend_from_slice(label);
    prf_input.push(0x00);
    prf_input.extend_from_slice(ctx);

    let expected_block = hmac_sha256(&k, &prf_input);
    let kdf_block = kdf_hmac_sha256(&k, label, ctx, 32);
    assert_eq!(&expected_block[..], &kdf_block[..]);
}

// ── hash_elems_v21 ─────────────────────────────────────────────────────────────

#[test]
fn hash_v21_output_in_range() {
    let key = ElementModQ::from_u64(1);
    let h = hash_elems_v21(&key, 0x00, &[HashableValue::U64(42)]).unwrap();
    assert!(*h.value() < Q_VALUE, "hash output must be < Q");
}

#[test]
fn hash_v21_deterministic() {
    let key = ElementModQ::from_u64(42);
    let h1 = hash_elems_v21(&key, 0x01, &[HashableValue::Str("hello")]).unwrap();
    let h2 = hash_elems_v21(&key, 0x01, &[HashableValue::Str("hello")]).unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn hash_v21_and_v21_q_are_aliases() {
    let key = ElementModQ::from_u64(99);
    let h1 = hash_elems_v21(&key, 0x10, &[HashableValue::U64(1)]).unwrap();
    let h2 = hash_elems_v21_q(&key, 0x10, &[HashableValue::U64(1)]).unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn hash_v21_domain_sep_changes_output() {
    let key = ElementModQ::from_u64(1);
    let args = &[HashableValue::U64(1)];
    let h0 = hash_elems_v21(&key, 0x00, args).unwrap();
    let h1 = hash_elems_v21(&key, 0x01, args).unwrap();
    assert_ne!(h0, h1);
}

#[test]
fn hash_v21_different_args_differ() {
    let key = ElementModQ::from_u64(1);
    let h1 = hash_elems_v21(&key, 0x00, &[HashableValue::U64(100)]).unwrap();
    let h2 = hash_elems_v21(&key, 0x00, &[HashableValue::U64(200)]).unwrap();
    assert_ne!(h1, h2);
}

#[test]
fn hash_v21_mod_p_arg() {
    let key = ElementModQ::from_u64(1);
    let g = electionguard_core2::ElementModP::g();
    let h = hash_elems_v21(&key, 0x20, &[HashableValue::ModP(g)]).unwrap();
    assert!(*h.value() < Q_VALUE);
}

#[test]
fn hash_v21_mod_q_arg() {
    let key = ElementModQ::from_u64(1);
    let q = ElementModQ::from_u64(42);
    let h = hash_elems_v21(&key, 0x00, &[HashableValue::ModQ(&q)]).unwrap();
    assert!(*h.value() < Q_VALUE);
}

#[test]
fn hash_v21_multiple_args() {
    let key = ElementModQ::from_u64(1);
    let g = electionguard_core2::ElementModP::g();
    let q = ElementModQ::from_u64(7);
    let h = hash_elems_v21(
        &key,
        0x00,
        &[
            HashableValue::ModP(g),
            HashableValue::ModQ(&q),
            HashableValue::U64(42),
            HashableValue::Str("hello"),
        ],
    )
    .unwrap();
    assert!(*h.value() < Q_VALUE);
}

#[test]
fn hash_v21_null_produces_valid_output() {
    let key = ElementModQ::from_u64(1);
    let h = hash_elems_v21(&key, 0x00, &[HashableValue::Null]).unwrap();
    assert!(*h.value() < Q_VALUE);
}

#[test]
fn hash_v21_bytes_arg() {
    let key = ElementModQ::from_u64(1);
    let data = b"test data bytes";
    let h = hash_elems_v21(&key, 0x00, &[HashableValue::Bytes(data.as_ref())]).unwrap();
    assert!(*h.value() < Q_VALUE);
}

#[test]
fn hash_v21_raw_zero_key() {
    let key = [0u8; 32];
    let h = hash_elems_v21_raw(
        &key,
        0x00,
        &[HashableValue::Str("v2.1")],
    )
    .unwrap();
    assert!(*h.value() < Q_VALUE);
}

/// Verify that parameter hash uses zero key (sanity check for future election.rs).
#[test]
fn parameter_hash_zero_key_changes_with_version() {
    let zero_key = [0u8; 32];
    let h1 = hash_elems_v21_raw(&zero_key, 0x00, &[HashableValue::Str("v2.1")]).unwrap();
    let h2 = hash_elems_v21_raw(&zero_key, 0x00, &[HashableValue::Str("v2.0")]).unwrap();
    assert_ne!(h1, h2);
}

// ── Nonces ────────────────────────────────────────────────────────────────────

#[test]
fn nonces_sequence_deterministic() {
    let seed = ElementModQ::from_u64(1234);
    let gen = Nonces::new(&seed);
    let a = gen.get(5).unwrap();
    let b = gen.get(5).unwrap();
    assert_eq!(a, b);
}

#[test]
fn nonces_with_header_differs_from_without() {
    let seed = ElementModQ::from_u64(1);
    let gen_bare = Nonces::new(&seed);
    let gen_hdr = Nonces::with_header(&seed, b"some-header");
    let n_bare = gen_bare.get(0).unwrap();
    let n_hdr = gen_hdr.get(0).unwrap();
    assert_ne!(n_bare, n_hdr, "header must change the nonce output");
}

#[test]
fn selection_enc_id_matches_formula() {
    // H_I = H(H_E; 0x20, ballot_id)
    let h_e = ElementModQ::from_u64(999);
    let ballot_id = ElementModQ::from_u64(42);
    let h_i = compute_selection_encryption_id(&h_e, &ballot_id).unwrap();

    // Manually compute using hash_elems_v21 to verify consistency.
    let expected = hash_elems_v21(
        &h_e,
        0x20,
        &[HashableValue::ModQ(&ballot_id)],
    )
    .unwrap();
    assert_eq!(h_i, expected);
}

#[test]
fn selection_nonce_matches_formula() {
    // ξ_{i,j} = H(H_I; 0x21, i, j, ξ_B)
    let h_i = ElementModQ::from_u64(100);
    let ballot_nonce = ElementModQ::from_u64(7);
    let nonce = derive_selection_nonce(&h_i, 1, 2, &ballot_nonce).unwrap();

    let expected = hash_elems_v21(
        &h_i,
        0x21,
        &[
            HashableValue::U64(1),
            HashableValue::U64(2),
            HashableValue::ModQ(&ballot_nonce),
        ],
    )
    .unwrap();
    assert_eq!(nonce, expected);
}

#[test]
fn contest_data_nonce_matches_formula() {
    // ξ = H(H_I; 0x25, ind_c, ξ_B)
    let h_i = ElementModQ::from_u64(100);
    let ballot_nonce = ElementModQ::from_u64(7);
    let nonce = derive_contest_data_nonce(&h_i, 3, &ballot_nonce).unwrap();

    let expected = hash_elems_v21(
        &h_i,
        0x25,
        &[
            HashableValue::U64(3),
            HashableValue::ModQ(&ballot_nonce),
        ],
    )
    .unwrap();
    assert_eq!(nonce, expected);
}

#[test]
fn hash_u64_serialization_truncates_to_32bit() {
    // u64 values are serialized as the low 32 bits in 4 BE bytes per spec.
    // So hash(key; 0x00, u64_val) == hash(key; 0x00, (u64_val as u32))
    // for values that fit in 32 bits.
    let key = ElementModQ::from_u64(1);
    let small_u64: u64 = 42;
    let h1 = hash_elems_v21(&key, 0x00, &[HashableValue::U64(small_u64)]).unwrap();
    // Same value with high 32 bits set → still gets truncated to low 32 bits (42).
    let big_u64: u64 = (0xDEAD_BEEF_u64 << 32) | 42;
    let h2 = hash_elems_v21(&key, 0x00, &[HashableValue::U64(big_u64)]).unwrap();
    assert_eq!(h1, h2, "u64 must be truncated to 32 bits for hashing");
}

// ── HashableValue From conversions ────────────────────────────────────────
//
// Lines 40-41, 46-47, 52-53, 58-59, 64-65 in src/hash.rs

use electionguard_core2::ElementModP;

#[test]
fn hashable_value_from_element_mod_p() {
    let p = ElementModP::g();
    let v: HashableValue<'_> = p.into();
    // Should produce HashableValue::ModP; verify it can be hashed
    let key = ElementModQ::from_u64(1);
    let h = hash_elems_v21(&key, 0x00, &[v]).unwrap();
    assert!(!h.is_zero());
}

#[test]
fn hashable_value_from_element_mod_q() {
    let q = ElementModQ::from_u64(99);
    let v: HashableValue<'_> = (&q).into();
    let key = ElementModQ::from_u64(1);
    let h = hash_elems_v21(&key, 0x00, &[v]).unwrap();
    assert!(!h.is_zero());
}

#[test]
fn hashable_value_from_u64() {
    let v: HashableValue<'_> = HashableValue::from(42u64);
    let key = ElementModQ::from_u64(1);
    let h = hash_elems_v21(&key, 0x00, &[v]).unwrap();
    assert!(!h.is_zero());
}

#[test]
fn hashable_value_from_str() {
    let s = "hello";
    let v: HashableValue<'_> = s.into();
    let key = ElementModQ::from_u64(1);
    let h = hash_elems_v21(&key, 0x00, &[v]).unwrap();
    assert!(!h.is_zero());
}

#[test]
fn hashable_value_from_bytes() {
    let bytes: &[u8] = b"raw bytes";
    let v: HashableValue<'_> = bytes.into();
    let key = ElementModQ::from_u64(1);
    let h = hash_elems_v21(&key, 0x00, &[v]).unwrap();
    assert!(!h.is_zero());
}

// ── Seq and Null variants (lines 111-112) ────────────────────────────────

#[test]
fn hash_with_seq_variant() {
    let key = ElementModQ::from_u64(1);
    let inner: Vec<HashableValue<'_>> = vec![
        HashableValue::U64(1),
        HashableValue::U64(2),
        HashableValue::U64(3),
    ];
    let h = hash_elems_v21(&key, 0x00, &[HashableValue::Seq(inner)]).unwrap();
    assert!(!h.is_zero());
}

#[test]
fn hash_with_null_variant() {
    let key = ElementModQ::from_u64(1);
    let h = hash_elems_v21(&key, 0x00, &[HashableValue::Null]).unwrap();
    assert!(!h.is_zero());
}

#[test]
fn hash_with_bytes_variant() {
    let key = ElementModQ::from_u64(1);
    let h = hash_elems_v21(&key, 0x00, &[HashableValue::Bytes(b"test")]).unwrap();
    assert!(!h.is_zero());
}

#[test]
fn seq_variant_matches_individual_elements() {
    // Hashing a Seq([a, b]) should be the same as hashing the elements inline
    let key = ElementModQ::from_u64(42);
    let h_seq = hash_elems_v21(
        &key,
        0x00,
        &[HashableValue::Seq(vec![
            HashableValue::U64(1),
            HashableValue::U64(2),
        ])],
    )
    .unwrap();
    let h_inline =
        hash_elems_v21(&key, 0x00, &[HashableValue::U64(1), HashableValue::U64(2)]).unwrap();
    assert_eq!(h_seq, h_inline, "Seq must serialize identically to inline elements");
}

// ── Nonces: get_with_header, get_range, next, reset, position ─────────────
//
// Lines 54, 56, 58, 63, 69 in src/nonces.rs

#[test]
fn nonces_get_with_header_is_deterministic() {
    let seed = ElementModQ::from_u64(100);
    let nonces = Nonces::new(&seed);
    let h1 = nonces.get_with_header(0, "ballot-id").unwrap();
    let h2 = nonces.get_with_header(0, "ballot-id").unwrap();
    assert_eq!(h1, h2, "get_with_header must be deterministic");
}

#[test]
fn nonces_get_with_header_differs_from_plain_get() {
    let seed = ElementModQ::from_u64(100);
    let nonces = Nonces::new(&seed);
    let h_plain = nonces.get(0).unwrap();
    let h_header = nonces.get_with_header(0, "prefix").unwrap();
    assert_ne!(h_plain, h_header, "get_with_header must differ from get");
}

#[test]
fn nonces_get_range_returns_correct_count() {
    let seed = ElementModQ::from_u64(7);
    let nonces = Nonces::new(&seed);
    let range = nonces.get_range(0, 5).unwrap();
    assert_eq!(range.len(), 5);
    // Each element must equal get(i)
    for (i, r) in range.iter().enumerate() {
        assert_eq!(*r, nonces.get(i as u64).unwrap());
    }
}

#[test]
fn nonces_next_advances_counter() {
    let seed = ElementModQ::from_u64(42);
    let mut nonces = Nonces::new(&seed);
    assert_eq!(nonces.position(), 0);
    let n0 = nonces.next().unwrap();
    assert_eq!(nonces.position(), 1);
    let n1 = nonces.next().unwrap();
    assert_eq!(nonces.position(), 2);
    assert_ne!(n0, n1, "consecutive nonces must differ");
    // n0 must equal get(0)
    assert_eq!(n0, nonces.get(0).unwrap());
}

#[test]
fn nonces_reset_restores_counter() {
    let seed = ElementModQ::from_u64(5);
    let mut nonces = Nonces::new(&seed);
    let _ = nonces.next().unwrap();
    let _ = nonces.next().unwrap();
    assert_eq!(nonces.position(), 2);
    nonces.reset();
    assert_eq!(nonces.position(), 0);
    let n0_after_reset = nonces.next().unwrap();
    assert_eq!(n0_after_reset, nonces.get(0).unwrap());
}
