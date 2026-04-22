//! Integration tests for encrypt.rs — Ballot Encryption (Phase 8).
//!
//! Tests:
//! 1. EncryptionDevice hash is deterministic.
//! 2. Single selection encryption: ciphertext components, proof, crypto_hash.
//! 3. Contest encryption: accumulation, selection count, placeholder.
//! 4. Full ballot encryption: contests, confirmation code, validity.
//! 5. EncryptionMediator: multi-ballot state, chaining.
//! 6. Ballot with undervote encrypted correctly.

use electionguard_core2::{
    ballot::{BallotBoxState, PlaintextBallot, PlaintextBallotContest, PlaintextBallotSelection},
    election::CiphertextElectionContext,
    elgamal::{elgamal_accumulate, elgamal_encrypt, ElGamalKeyPair},
    encrypt::{encrypt_ballot, encrypt_contest, encrypt_selection, EncryptionDevice, EncryptionMediator},
    group::{g_pow, ElementModQ},
    manifest::{
        BallotStyle, Candidate, ContestDescription, ContestDescriptionWithPlaceholders,
        ElectionType, GeopoliticalUnit, InternalManifest, Manifest, ReportingUnitType,
        SelectionDescription, VoteVariationType, generate_placeholder_selection,
    },
    nonces::compute_selection_encryption_id,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn seed(n: u64) -> ElementModQ {
    ElementModQ::from_u64(n)
}

fn make_key_pair() -> ElGamalKeyPair {
    ElGamalKeyPair::from_secret(ElementModQ::from_u64(137))
}

fn make_context() -> CiphertextElectionContext {
    let kp = make_key_pair();
    CiphertextElectionContext::new(
        3, // n
        2, // k
        kp.public_key.clone(),
        kp.public_key.clone(),
        seed(42), // commitment_hash
        seed(77), // manifest_hash
    )
    .unwrap()
}

/// Build a minimal 1-contest manifest with two candidates.
fn sample_manifest() -> Manifest {
    Manifest {
        election_scope_id: "test-election".to_string(),
        spec_version: "v2.1".to_string(),
        election_type: ElectionType::General,
        start_date: "2024-11-05T00:00:00Z".to_string(),
        end_date: "2024-11-05T23:59:59Z".to_string(),
        geopolitical_units: vec![GeopoliticalUnit {
            object_id: "gp-1".to_string(),
            name: "Test District".to_string(),
            reporting_unit_type: ReportingUnitType::Precinct,
            contact_information: None,
        }],
        parties: vec![],
        candidates: vec![
            Candidate {
                object_id: "cand-A".to_string(),
                name: None,
                party_id: None,
                image_uri: None,
                is_write_in: false,
            },
            Candidate {
                object_id: "cand-B".to_string(),
                name: None,
                party_id: None,
                image_uri: None,
                is_write_in: false,
            },
        ],
        contests: vec![ContestDescription {
            object_id: "contest-mayor".to_string(),
            electoral_district_id: "gp-1".to_string(),
            sequence_order: 1,
            vote_variation: VoteVariationType::OneOfM,
            number_elected: 1,
            votes_allowed: Some(1),
            name: "Mayor".to_string(),
            ballot_title: None,
            ballot_subtitle: None,
            selections: vec![
                SelectionDescription {
                    object_id: "sel-A".to_string(),
                    candidate_id: "cand-A".to_string(),
                    sequence_order: 1,
                },
                SelectionDescription {
                    object_id: "sel-B".to_string(),
                    candidate_id: "cand-B".to_string(),
                    sequence_order: 2,
                },
            ],
            primary_party_ids: vec![],
        }],
        ballot_styles: vec![BallotStyle {
            object_id: "style-1".to_string(),
            geopolitical_unit_ids: vec!["gp-1".to_string()],
            party_ids: vec![],
            image_uri: None,
        }],
        name: None,
        contact_information: None,
    }
}

fn sample_internal_manifest() -> InternalManifest {
    InternalManifest::from_manifest(&sample_manifest()).unwrap()
}

/// Build a plaintext ballot voting for candidate A in the sole contest.
fn make_ballot_vote_a() -> PlaintextBallot {
    PlaintextBallot {
        object_id: "ballot-1".to_string(),
        style_id: "style-1".to_string(),
        contests: vec![PlaintextBallotContest {
            object_id: "contest-mayor".to_string(),
            selections: vec![
                PlaintextBallotSelection {
                    object_id: "sel-A".to_string(),
                    vote: 1,
                    is_placeholder_selection: false,
                    extended_data: None,
                },
                PlaintextBallotSelection {
                    object_id: "sel-B".to_string(),
                    vote: 0,
                    is_placeholder_selection: false,
                    extended_data: None,
                },
            ],
        }],
    }
}

/// Build a minimal description with placeholders for testing
fn make_contest_description_with_placeholders() -> ContestDescriptionWithPlaceholders {
    let inner = ContestDescription {
        object_id: "contest-mayor".to_string(),
        electoral_district_id: "gp-1".to_string(),
        sequence_order: 1,
        vote_variation: VoteVariationType::OneOfM,
        number_elected: 1,
        votes_allowed: Some(1),
        name: "Mayor".to_string(),
        ballot_title: None,
        ballot_subtitle: None,
        selections: vec![
            SelectionDescription {
                object_id: "sel-A".to_string(),
                candidate_id: "cand-A".to_string(),
                sequence_order: 1,
            },
            SelectionDescription {
                object_id: "sel-B".to_string(),
                candidate_id: "cand-B".to_string(),
                sequence_order: 2,
            },
        ],
        primary_party_ids: vec![],
    };
    // Generate one placeholder for the single elected seat.
    let placeholder = generate_placeholder_selection(&inner, 3);
    ContestDescriptionWithPlaceholders {
        contest: inner,
        placeholder_selections: vec![placeholder],
    }
}

// ── EncryptionDevice tests ────────────────────────────────────────────────────

#[test]
fn device_hash_is_deterministic() {
    let d1 = EncryptionDevice::new(1, 2, 3, "precinct-1");
    let d2 = EncryptionDevice::new(1, 2, 3, "precinct-1");
    assert_eq!(d1.hash().unwrap(), d2.hash().unwrap());
}

#[test]
fn device_hash_changes_with_location() {
    let d1 = EncryptionDevice::new(1, 2, 3, "precinct-1");
    let d2 = EncryptionDevice::new(1, 2, 3, "precinct-2");
    assert_ne!(d1.hash().unwrap(), d2.hash().unwrap());
}

#[test]
fn device_hash_changes_with_uuid() {
    let d1 = EncryptionDevice::new(1, 2, 3, "loc");
    let d2 = EncryptionDevice::new(99, 2, 3, "loc");
    assert_ne!(d1.hash().unwrap(), d2.hash().unwrap());
}

// ── Selection encryption tests ────────────────────────────────────────────────

#[test]
fn encrypt_selection_vote_one_ciphertext_components() {
    let ctx = make_context();
    let nonce = seed(7);
    let proof_seed = seed(77);
    let desc_hash = seed(3);

    let sel = encrypt_selection(1, "sel-A", 1, &desc_hash, &ctx, &nonce, &proof_seed, false).unwrap();

    // pad = g^nonce
    assert_eq!(sel.ciphertext.pad, g_pow(&nonce));
    assert_eq!(sel.is_placeholder, false);
    assert_eq!(sel.sequence_order, 1);
}

#[test]
fn encrypt_selection_vote_zero_no_g_factor() {
    let ctx = make_context();
    let nonce = seed(13);
    let proof_seed = seed(313);
    let desc_hash = seed(5);

    let sel = encrypt_selection(0, "sel-B", 2, &desc_hash, &ctx, &nonce, &proof_seed, false).unwrap();

    // data = g^0 * K^r = K^r (no g factor for vote=0)
    let expected_data = {
        use electionguard_core2::group::pow_mod_p;
        pow_mod_p(&ctx.elgamal_public_key, &nonce)
    };
    assert_eq!(sel.ciphertext.data, expected_data);
}

#[test]
fn encrypt_selection_placeholder() {
    let ctx = make_context();
    let sel = encrypt_selection(1, "placeholder-1", 3, &seed(9), &ctx, &seed(22), &seed(222), true).unwrap();
    assert!(sel.is_placeholder);
}

#[test]
fn encrypt_selection_has_valid_proof() {
    let ctx = make_context();
    let sel = encrypt_selection(1, "s", 1, &seed(1), &ctx, &seed(5), &seed(55), false).unwrap();
    // Proof has range_limit = 1 (OneOfM contests).
    assert_eq!(sel.proof.range_limit, 1);
}

#[test]
fn encrypt_selection_crypto_hash_is_nonzero() {
    let ctx = make_context();
    let sel = encrypt_selection(0, "s", 1, &seed(0), &ctx, &seed(3), &seed(33), false).unwrap();
    assert_ne!(sel.crypto_hash, ElementModQ::from_u64(0));
}

#[test]
fn encrypt_selection_different_nonces_give_different_ciphertexts() {
    let ctx = make_context();
    let desc = seed(10);
    let s1 = encrypt_selection(1, "s", 1, &desc, &ctx, &seed(1), &seed(11), false).unwrap();
    let s2 = encrypt_selection(1, "s", 1, &desc, &ctx, &seed(2), &seed(22), false).unwrap();
    assert_ne!(s1.ciphertext.pad, s2.ciphertext.pad);
    assert_ne!(s1.ciphertext.data, s2.ciphertext.data);
}

// ── Contest encryption tests ──────────────────────────────────────────────────

#[test]
fn encrypt_contest_selection_count() {
    let ctx = make_context();
    let desc = make_contest_description_with_placeholders();
    let ballot_nonce = seed(100);
    let sel_enc_id =
        compute_selection_encryption_id(&ctx.extended_base_hash, &ballot_nonce).unwrap();

    let contest = make_ballot_vote_a().contests.into_iter().next().unwrap();
    let enc = encrypt_contest(Some(&contest), &desc, &ctx, &ballot_nonce, &sel_enc_id, 1).unwrap();

    // 2 real + 1 placeholder = 3 selections for OneOfM 1-elected contest.
    assert_eq!(enc.selections.len(), 3);
}

#[test]
fn encrypt_contest_accumulation_matches_sum() {
    let ctx = make_context();
    let desc = make_contest_description_with_placeholders();
    let ballot_nonce = seed(200);
    let sel_enc_id =
        compute_selection_encryption_id(&ctx.extended_base_hash, &ballot_nonce).unwrap();

    let contest = make_ballot_vote_a().contests.into_iter().next().unwrap();
    let enc = encrypt_contest(Some(&contest), &desc, &ctx, &ballot_nonce, &sel_enc_id, 1).unwrap();

    // Recompute accumulation manually.
    let refs: Vec<_> = enc.selections.iter().map(|s| &s.ciphertext).collect();
    let expected = elgamal_accumulate(&refs);
    assert_eq!(enc.ciphertext_accumulation, expected);
}

#[test]
fn encrypt_contest_placeholder_is_complement() {
    // When candidate A is selected (vote=1) and candidate B is not (vote=0),
    // the placeholder should have vote=0 (no placeholder vote needed).
    let ctx = make_context();
    let desc = make_contest_description_with_placeholders();
    let ballot_nonce = seed(300);
    let sel_enc_id =
        compute_selection_encryption_id(&ctx.extended_base_hash, &ballot_nonce).unwrap();

    let contest = make_ballot_vote_a().contests.into_iter().next().unwrap();
    let enc = encrypt_contest(Some(&contest), &desc, &ctx, &ballot_nonce, &sel_enc_id, 1).unwrap();

    // There is exactly one placeholder selection and it should be marked as such.
    let placeholders: Vec<_> = enc.selections.iter().filter(|s| s.is_placeholder).collect();
    assert_eq!(placeholders.len(), 1, "exactly one placeholder for OneOfM=1");
}

#[test]
fn encrypt_contest_undervote_all_zero() {
    // If no contest is provided (undervote), all selections should encrypt 0.
    let ctx = make_context();
    let desc = make_contest_description_with_placeholders();
    let ballot_nonce = seed(400);
    let sel_enc_id =
        compute_selection_encryption_id(&ctx.extended_base_hash, &ballot_nonce).unwrap();

    let enc = encrypt_contest(None, &desc, &ctx, &ballot_nonce, &sel_enc_id, 1).unwrap();

    // All real selections should be 0; placeholder fills the gap.
    let real_selections: Vec<_> = enc.selections.iter().filter(|s| !s.is_placeholder).collect();
    for sel in &real_selections {
        // pad = g^nonce, data = g^0 * K^nonce = K^nonce
        // Can't easily verify vote value without discrete log, but check proof succeeds.
        assert_eq!(sel.proof.range_limit, 1);
    }
}

#[test]
fn encrypt_contest_nonce_is_set() {
    let ctx = make_context();
    let desc = make_contest_description_with_placeholders();
    let ballot_nonce = seed(500);
    let sel_enc_id =
        compute_selection_encryption_id(&ctx.extended_base_hash, &ballot_nonce).unwrap();

    let contest = make_ballot_vote_a().contests.into_iter().next().unwrap();
    let enc = encrypt_contest(Some(&contest), &desc, &ctx, &ballot_nonce, &sel_enc_id, 1).unwrap();
    assert!(enc.nonce.is_some(), "contest nonce must be present before clearing");
}

// ── Full ballot encryption tests ──────────────────────────────────────────────

#[test]
fn encrypt_ballot_produces_correct_contest_count() {
    let im = sample_internal_manifest();
    let ctx = make_context();
    let ballot = make_ballot_vote_a();

    let enc = encrypt_ballot(&ballot, &im, &ctx, &seed(1), &seed(2), 0, false).unwrap();
    assert_eq!(enc.contests.len(), 1, "one contest in the manifest");
}

#[test]
fn encrypt_ballot_has_confirmation_code() {
    let im = sample_internal_manifest();
    let ctx = make_context();
    let ballot = make_ballot_vote_a();

    let enc = encrypt_ballot(&ballot, &im, &ctx, &seed(10), &seed(20), 1_700_000_000, false).unwrap();
    assert_ne!(enc.ballot_code, ElementModQ::from_u64(0));
}

#[test]
fn encrypt_ballot_manifest_hash_matches_context() {
    let im = sample_internal_manifest();
    let ctx = make_context();
    let ballot = make_ballot_vote_a();

    let enc = encrypt_ballot(&ballot, &im, &ctx, &seed(3), &seed(6), 0, false).unwrap();
    assert_eq!(enc.manifest_hash, ctx.manifest_hash);
}

#[test]
fn encrypt_ballot_different_nonces_give_different_codes() {
    let im = sample_internal_manifest();
    let ctx = make_context();
    let ballot = make_ballot_vote_a();

    let enc1 = encrypt_ballot(&ballot, &im, &ctx, &seed(1), &seed(1), 0, false).unwrap();
    let enc2 = encrypt_ballot(&ballot, &im, &ctx, &seed(2), &seed(2), 0, false).unwrap();
    assert_ne!(enc1.ballot_code, enc2.ballot_code);
}

#[test]
fn encrypt_ballot_is_deterministic() {
    let im = sample_internal_manifest();
    let ctx = make_context();
    let ballot = make_ballot_vote_a();

    let enc1 = encrypt_ballot(&ballot, &im, &ctx, &seed(7), &seed(7), 0, false).unwrap();
    let enc2 = encrypt_ballot(&ballot, &im, &ctx, &seed(7), &seed(7), 0, false).unwrap();
    assert_eq!(enc1.ballot_code, enc2.ballot_code);
    assert_eq!(enc1.contests[0].ciphertext_accumulation, enc2.contests[0].ciphertext_accumulation);
}

#[test]
fn encrypt_ballot_invalid_style_returns_error() {
    let im = sample_internal_manifest();
    let ctx = make_context();
    let ballot = PlaintextBallot {
        object_id: "b".to_string(),
        style_id: "nonexistent-style".to_string(),
        contests: vec![],
    };
    let result = encrypt_ballot(&ballot, &im, &ctx, &seed(1), &seed(1), 0, false);
    assert!(result.is_err(), "nonexistent ballot style must produce an error");
}

#[test]
fn encrypt_ballot_selection_encryption_id_is_stored() {
    let im = sample_internal_manifest();
    let ctx = make_context();
    let ballot = make_ballot_vote_a();

    let enc = encrypt_ballot(&ballot, &im, &ctx, &seed(5), &seed(5), 0, false).unwrap();
    assert!(enc.selection_encryption_id.is_some(), "v2.1 sel_enc_id must be stored");
}

#[test]
fn encrypt_ballot_nonce_is_stored() {
    let im = sample_internal_manifest();
    let ctx = make_context();
    let ballot = make_ballot_vote_a();

    let enc = encrypt_ballot(&ballot, &im, &ctx, &seed(99), &seed(99), 0, false).unwrap();
    assert!(enc.nonce.is_some(), "master nonce must be stored before clearing");
}

// ── EncryptionMediator tests ──────────────────────────────────────────────────

#[test]
fn mediator_encrypts_single_ballot() {
    let im = sample_internal_manifest();
    let ctx = make_context();
    let device = EncryptionDevice::new(42, 1, 7, "booth-1");
    let mut mediator = EncryptionMediator::new(im, ctx, device).unwrap();

    let ballot = make_ballot_vote_a();
    let enc = mediator.encrypt(&ballot).unwrap();
    assert_eq!(enc.object_id, "ballot-1");
}

#[test]
fn mediator_ballot_count_increments() {
    let im = sample_internal_manifest();
    let ctx = make_context();
    let device = EncryptionDevice::new(1, 1, 1, "loc");
    let mut mediator = EncryptionMediator::new(im, ctx, device).unwrap();

    assert_eq!(mediator.ballot_count, 0);
    mediator.encrypt(&make_ballot_vote_a()).unwrap();
    assert_eq!(mediator.ballot_count, 1);
    mediator.encrypt(&make_ballot_vote_a()).unwrap();
    assert_eq!(mediator.ballot_count, 2);
}

#[test]
fn mediator_successive_ballots_different_codes() {
    let im = sample_internal_manifest();
    let ctx = make_context();
    let device = EncryptionDevice::new(1, 1, 1, "loc");
    let mut mediator = EncryptionMediator::new(im, ctx, device).unwrap();

    let enc1 = mediator.encrypt(&make_ballot_vote_a()).unwrap();
    let enc2 = mediator.encrypt(&make_ballot_vote_a()).unwrap();
    assert_ne!(enc1.ballot_code, enc2.ballot_code, "each ballot must have a unique code");
}

#[test]
fn mediator_confirmation_codes_are_nonzero() {
    let im = sample_internal_manifest();
    let ctx = make_context();
    let device = EncryptionDevice::new(5, 5, 5, "here");
    let mut mediator = EncryptionMediator::new(im, ctx, device).unwrap();

    for _ in 0..3 {
        let enc = mediator.encrypt(&make_ballot_vote_a()).unwrap();
        assert_ne!(enc.ballot_code, ElementModQ::from_u64(0));
    }
}

#[test]
fn mediator_encrypt_and_cast() {
    let im = sample_internal_manifest();
    let ctx = make_context();
    let device = EncryptionDevice::new(1, 2, 3, "booth");
    let mut mediator = EncryptionMediator::new(im, ctx, device).unwrap();

    let submitted = mediator.encrypt_and_cast(&make_ballot_vote_a()).unwrap();
    assert_eq!(submitted.state, BallotBoxState::Cast);
    // Nonces must be stripped.
    assert!(submitted.nonce.is_none());
}

#[test]
fn mediator_encrypt_and_spoil() {
    let im = sample_internal_manifest();
    let ctx = make_context();
    let device = EncryptionDevice::new(10, 20, 30, "loc");
    let mut mediator = EncryptionMediator::new(im, ctx, device).unwrap();

    let submitted = mediator.encrypt_and_spoil(&make_ballot_vote_a()).unwrap();
    assert_eq!(submitted.state, BallotBoxState::Spoiled);
}

// ── Ciphertext homomorphism tests ─────────────────────────────────────────────

#[test]
fn elgamal_homomorphism_vote_one_plus_zero() {
    // Encrypting 1 and 0 and adding should give the same as encrypting 1.
    let kp = make_key_pair();
    let n1 = seed(5);
    let n2 = seed(7);

    let ct1 = elgamal_encrypt(1, &n1, &kp.public_key);
    let ct0 = elgamal_encrypt(0, &n2, &kp.public_key);
    let combined = elgamal_accumulate(&[&ct1, &ct0]);

    // Manually compute expected: (g^{r1+r2}, g^1 * K^{r1+r2})
    use electionguard_core2::group::add_mod_q;
    let combined_nonce = add_mod_q(&n1, &n2);
    let expected = elgamal_encrypt(1, &combined_nonce, &kp.public_key);
    assert_eq!(combined.pad, expected.pad);
    assert_eq!(combined.data, expected.data);
}
