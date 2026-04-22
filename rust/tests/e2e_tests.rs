//! End-to-end (Phase 11) integration tests for ElectionGuard v2.1.
//!
//! Exercises the full election lifecycle:
//!   1.  Manifest creation (2 contests: President + Proposition 1)
//!   2.  Guardian key ceremony – key generation (n=3, k=2 threshold)
//!   3.  Encrypted share exchange + Schnorr proof verification
//!   4.  Election context construction (joint key, hash chain)
//!   5.  Ballot encryption via EncryptionMediator (5 ballots)
//!   6.  Ballot submission (cast 4, spoil 1)
//!   7.  Homomorphic tally accumulation over cast ballots
//!   8.  Threshold decryption (2-of-3 guardians via Shamir + Lagrange)
//!   9.  Chaum-Pedersen proof verification for every decryption share
//!  10.  Final tally verification against expected plaintext totals
//!
//! Additional focused tests:
//!  – `test_key_ceremony_share_exchange`   – share exchange between 3 guardians
//!  – `test_ballot_encryption_and_cast`    – encryption + nonce clearing
//!  – `test_homomorphic_tally`             – accumulation matches manual count
//!  – `test_threshold_decryption_2_of_3`   – decrypt with exactly 2 of 3 guardians

use std::collections::HashMap;

use electionguard_core2::{
    ballot::{
        BallotBoxState, PlaintextBallot, PlaintextBallotContest, PlaintextBallotSelection,
        SubmittedBallot,
    },
    decryption::{
        combine_partial_decryptions, compute_decryption_share, decrypt_tally_with_shares,
        verify_decryption_proof, PartialDecryption, TallyDecryptionShare,
    },
    discrete_log::DiscreteLogTable,
    election::{compute_parameter_hash, CiphertextElectionContext},
    elgamal::{elgamal_accumulate, elgamal_encrypt, ElGamalCiphertext},
    encrypt::{EncryptionDevice, EncryptionMediator},
    group::{add_mod_q, div_mod_p, g_pow, ElementModP, ElementModQ},
    guardian::{
        compute_joint_key, compute_polynomial_coordinate, decrypt_share,
        generate_election_key_pair, generate_election_partial_key_backup,
        generate_guardian_proofs, verify_election_partial_key_backup, verify_schnorr_proof,
    },
    hash::CryptoHashable,
    manifest::{
        BallotStyle, Candidate, ContestDescription, GeopoliticalUnit, InternalManifest, Manifest,
        ElectionType, ReportingUnitType, SelectionDescription, VoteVariationType,
    },
};
use electionguard_core2::decryption::compute_lagrange_coefficient;

// ═══════════════════════════════════════════════════════════════════════════════
// Fixture helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Build the 2-contest election manifest used by all E2E tests.
///
/// Contest layout:
/// - "contest-president"  → Alice (seq 1), Bob (seq 2), Charlie (seq 3) – elect 1
/// - "contest-prop1"      → Yes (seq 1), No (seq 2) – elect 1
fn make_manifest() -> Manifest {
    Manifest {
        election_scope_id: "e2e-election-2024".to_string(),
        spec_version: "v2.1".to_string(),
        election_type: ElectionType::General,
        start_date: "2024-11-05T00:00:00Z".to_string(),
        end_date: "2024-11-05T23:59:59Z".to_string(),
        geopolitical_units: vec![GeopoliticalUnit {
            object_id: "gp-1".to_string(),
            name: "County 1".to_string(),
            reporting_unit_type: ReportingUnitType::County,
            contact_information: None,
        }],
        parties: vec![],
        candidates: vec![
            Candidate {
                object_id: "alice".to_string(),
                name: None,
                party_id: None,
                image_uri: None,
                is_write_in: false,
            },
            Candidate {
                object_id: "bob".to_string(),
                name: None,
                party_id: None,
                image_uri: None,
                is_write_in: false,
            },
            Candidate {
                object_id: "charlie".to_string(),
                name: None,
                party_id: None,
                image_uri: None,
                is_write_in: false,
            },
            Candidate {
                object_id: "yes-cand".to_string(),
                name: None,
                party_id: None,
                image_uri: None,
                is_write_in: false,
            },
            Candidate {
                object_id: "no-cand".to_string(),
                name: None,
                party_id: None,
                image_uri: None,
                is_write_in: false,
            },
        ],
        contests: vec![
            ContestDescription {
                object_id: "contest-president".to_string(),
                electoral_district_id: "gp-1".to_string(),
                sequence_order: 1,
                vote_variation: VoteVariationType::OneOfM,
                number_elected: 1,
                votes_allowed: Some(1),
                name: "President".to_string(),
                ballot_title: None,
                ballot_subtitle: None,
                selections: vec![
                    SelectionDescription {
                        object_id: "sel-alice".to_string(),
                        candidate_id: "alice".to_string(),
                        sequence_order: 1,
                    },
                    SelectionDescription {
                        object_id: "sel-bob".to_string(),
                        candidate_id: "bob".to_string(),
                        sequence_order: 2,
                    },
                    SelectionDescription {
                        object_id: "sel-charlie".to_string(),
                        candidate_id: "charlie".to_string(),
                        sequence_order: 3,
                    },
                ],
                primary_party_ids: vec![],
            },
            ContestDescription {
                object_id: "contest-prop1".to_string(),
                electoral_district_id: "gp-1".to_string(),
                sequence_order: 2,
                vote_variation: VoteVariationType::OneOfM,
                number_elected: 1,
                votes_allowed: Some(1),
                name: "Proposition 1".to_string(),
                ballot_title: None,
                ballot_subtitle: None,
                selections: vec![
                    SelectionDescription {
                        object_id: "sel-yes".to_string(),
                        candidate_id: "yes-cand".to_string(),
                        sequence_order: 1,
                    },
                    SelectionDescription {
                        object_id: "sel-no".to_string(),
                        candidate_id: "no-cand".to_string(),
                        sequence_order: 2,
                    },
                ],
                primary_party_ids: vec![],
            },
        ],
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

/// Build a full plaintext ballot for "style-1".
///
/// `president_sel` is the `object_id` of the chosen president selection
/// (one of "sel-alice", "sel-bob", "sel-charlie").
///
/// `prop1_sel` is the `object_id` of the chosen proposition selection
/// (one of "sel-yes", "sel-no").
fn make_ballot(id: &str, president_sel: &str, prop1_sel: &str) -> PlaintextBallot {
    let pres_ids = ["sel-alice", "sel-bob", "sel-charlie"];
    let prop_ids = ["sel-yes", "sel-no"];

    PlaintextBallot {
        object_id: id.to_string(),
        style_id: "style-1".to_string(),
        contests: vec![
            PlaintextBallotContest {
                object_id: "contest-president".to_string(),
                selections: pres_ids
                    .iter()
                    .map(|&sid| PlaintextBallotSelection {
                        object_id: sid.to_string(),
                        vote: if sid == president_sel { 1 } else { 0 },
                        is_placeholder_selection: false,
                        extended_data: None,
                    })
                    .collect(),
            },
            PlaintextBallotContest {
                object_id: "contest-prop1".to_string(),
                selections: prop_ids
                    .iter()
                    .map(|&sid| PlaintextBallotSelection {
                        object_id: sid.to_string(),
                        vote: if sid == prop1_sel { 1 } else { 0 },
                        is_placeholder_selection: false,
                        extended_data: None,
                    })
                    .collect(),
            },
        ],
    }
}

/// Homomorphically accumulate the non-placeholder ciphertexts of all cast
/// ballots into a `contest_id → selection_id → ElGamalCiphertext` map.
fn accumulate_tally(
    cast_ballots: &[&SubmittedBallot],
) -> HashMap<String, HashMap<String, ElGamalCiphertext>> {
    let mut groups: HashMap<String, HashMap<String, Vec<ElGamalCiphertext>>> = HashMap::new();
    for ballot in cast_ballots {
        for contest in &ballot.contests {
            for sel in &contest.selections {
                if !sel.is_placeholder {
                    groups
                        .entry(contest.object_id.clone())
                        .or_default()
                        .entry(sel.object_id.clone())
                        .or_default()
                        .push(sel.ciphertext.clone());
                }
            }
        }
    }
    groups
        .into_iter()
        .map(|(contest_id, sel_map)| {
            let acc = sel_map
                .into_iter()
                .map(|(sel_id, cts)| {
                    let refs: Vec<&ElGamalCiphertext> = cts.iter().collect();
                    (sel_id, elgamal_accumulate(&refs))
                })
                .collect();
            (contest_id, acc)
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 1: Full election lifecycle
// ═══════════════════════════════════════════════════════════════════════════════

/// Full end-to-end election lifecycle with 3 guardians, k=2 threshold.
///
/// Ballot pattern (5 ballots total):
/// - ballot-1: Alice + Yes  → **Cast**
/// - ballot-2: Bob   + No   → **Cast**
/// - ballot-3: Alice + Yes  → **Cast**
/// - ballot-4: Charlie + No → **Spoiled** (does not count)
/// - ballot-5: Bob   + Yes  → **Cast**
///
/// Expected cast tally:
/// - President : Alice=2, Bob=2, Charlie=0
/// - Prop 1    : Yes=3,  No=1
#[test]
fn full_election_lifecycle() {
    // ── Step 1: Create manifest ──────────────────────────────────────────────
    let manifest = make_manifest();
    let manifest_hash = manifest.crypto_hash().unwrap();
    let internal_manifest = InternalManifest::from_manifest(&manifest).unwrap();

    // ── Step 2: Generate guardian key pairs (n=3, k=2) ───────────────────────
    let quorum = 2u32;

    let (key_set1, coeff1, pub_key1) = generate_election_key_pair(
        "guardian-1",
        1,
        quorum,
        &ElementModQ::from_u64(101),
    )
    .unwrap();
    let (key_set2, coeff2, pub_key2) = generate_election_key_pair(
        "guardian-2",
        2,
        quorum,
        &ElementModQ::from_u64(202),
    )
    .unwrap();
    let (key_set3, coeff3, pub_key3) = generate_election_key_pair(
        "guardian-3",
        3,
        quorum,
        &ElementModQ::from_u64(303),
    )
    .unwrap();

    // ── Step 3: Key ceremony – Schnorr proofs ────────────────────────────────
    let parameter_hash = compute_parameter_hash().unwrap();

    let (vote_proof1, data_proof1) = generate_guardian_proofs(
        &key_set1,
        &parameter_hash,
        &ElementModQ::from_u64(111),
    )
    .unwrap();
    let (vote_proof2, data_proof2) = generate_guardian_proofs(
        &key_set2,
        &parameter_hash,
        &ElementModQ::from_u64(222),
    )
    .unwrap();
    let (vote_proof3, data_proof3) = generate_guardian_proofs(
        &key_set3,
        &parameter_hash,
        &ElementModQ::from_u64(333),
    )
    .unwrap();

    // Verify all vote Schnorr proofs
    for p in &vote_proof1.proofs {
        assert!(verify_schnorr_proof(p, &parameter_hash), "G1 vote Schnorr proof invalid");
    }
    for p in &vote_proof2.proofs {
        assert!(verify_schnorr_proof(p, &parameter_hash), "G2 vote Schnorr proof invalid");
    }
    for p in &vote_proof3.proofs {
        assert!(verify_schnorr_proof(p, &parameter_hash), "G3 vote Schnorr proof invalid");
    }
    // Verify all data Schnorr proofs
    for p in &data_proof1.proofs {
        assert!(verify_schnorr_proof(p, &parameter_hash), "G1 data Schnorr proof invalid");
    }
    for p in &data_proof2.proofs {
        assert!(verify_schnorr_proof(p, &parameter_hash), "G2 data Schnorr proof invalid");
    }
    for p in &data_proof3.proofs {
        assert!(verify_schnorr_proof(p, &parameter_hash), "G3 data Schnorr proof invalid");
    }

    // ── Step 3 (cont.): Share exchange ───────────────────────────────────────
    //
    // Guardian i generates an encrypted backup of f_i(j) for every j ≠ i.
    // share_{i}_for_{j}  =  f_i(j)  encrypted under guardian j's comm key.

    // Guardian 1 → 2 : f_1(2)
    let share_1_for_2 = generate_election_partial_key_backup(
        "guardian-1",
        "guardian-2",
        2,
        &coeff1.coefficients,
        &key_set2.comm_key_pair.public_key,
    )
    .unwrap();
    // Guardian 1 → 3 : f_1(3)
    let share_1_for_3 = generate_election_partial_key_backup(
        "guardian-1",
        "guardian-3",
        3,
        &coeff1.coefficients,
        &key_set3.comm_key_pair.public_key,
    )
    .unwrap();
    // Guardian 2 → 1 : f_2(1)
    let share_2_for_1 = generate_election_partial_key_backup(
        "guardian-2",
        "guardian-1",
        1,
        &coeff2.coefficients,
        &key_set1.comm_key_pair.public_key,
    )
    .unwrap();
    // Guardian 2 → 3 : f_2(3)
    let share_2_for_3 = generate_election_partial_key_backup(
        "guardian-2",
        "guardian-3",
        3,
        &coeff2.coefficients,
        &key_set3.comm_key_pair.public_key,
    )
    .unwrap();
    // Guardian 3 → 1 : f_3(1)
    let share_3_for_1 = generate_election_partial_key_backup(
        "guardian-3",
        "guardian-1",
        1,
        &coeff3.coefficients,
        &key_set1.comm_key_pair.public_key,
    )
    .unwrap();
    // Guardian 3 → 2 : f_3(2)
    let share_3_for_2 = generate_election_partial_key_backup(
        "guardian-3",
        "guardian-2",
        2,
        &coeff3.coefficients,
        &key_set2.comm_key_pair.public_key,
    )
    .unwrap();

    // Every recipient verifies the share it received.
    assert!(
        verify_election_partial_key_backup(
            &share_1_for_2,
            &key_set2.comm_key_pair.secret_key,
            2,
            &pub_key1.vote_commitments
        )
        .unwrap(),
        "share_1_for_2 invalid"
    );
    assert!(
        verify_election_partial_key_backup(
            &share_1_for_3,
            &key_set3.comm_key_pair.secret_key,
            3,
            &pub_key1.vote_commitments
        )
        .unwrap(),
        "share_1_for_3 invalid"
    );
    assert!(
        verify_election_partial_key_backup(
            &share_2_for_1,
            &key_set1.comm_key_pair.secret_key,
            1,
            &pub_key2.vote_commitments
        )
        .unwrap(),
        "share_2_for_1 invalid"
    );
    assert!(
        verify_election_partial_key_backup(
            &share_2_for_3,
            &key_set3.comm_key_pair.secret_key,
            3,
            &pub_key2.vote_commitments
        )
        .unwrap(),
        "share_2_for_3 invalid"
    );
    assert!(
        verify_election_partial_key_backup(
            &share_3_for_1,
            &key_set1.comm_key_pair.secret_key,
            1,
            &pub_key3.vote_commitments
        )
        .unwrap(),
        "share_3_for_1 invalid"
    );
    assert!(
        verify_election_partial_key_backup(
            &share_3_for_2,
            &key_set2.comm_key_pair.secret_key,
            2,
            &pub_key3.vote_commitments
        )
        .unwrap(),
        "share_3_for_2 invalid"
    );

    // ── Step 4: Build election context ───────────────────────────────────────
    //
    // Joint vote key  K  = K_1 · K_2 · K_3
    // Joint data key  K̂  = K̂_1 · K̂_2 · K̂_3
    let joint_vote_key = compute_joint_key(&[
        key_set1.vote_key_pair.public_key.clone(),
        key_set2.vote_key_pair.public_key.clone(),
        key_set3.vote_key_pair.public_key.clone(),
    ]);
    let joint_data_key = compute_joint_key(&[
        key_set1.data_key_pair.public_key.clone(),
        key_set2.data_key_pair.public_key.clone(),
        key_set3.data_key_pair.public_key.clone(),
    ]);

    // Use zero commitment hash for simplicity (matches existing unit-test convention).
    let context = CiphertextElectionContext::new(
        3,
        2,
        joint_vote_key,
        joint_data_key,
        ElementModQ::from_u64(0),
        manifest_hash,
    )
    .unwrap();

    // ── Step 5: Encrypt 5 ballots via EncryptionMediator ─────────────────────
    let device = EncryptionDevice::new(42, 1, 1, "test-precinct");
    let mut mediator =
        EncryptionMediator::new(internal_manifest.clone(), context.clone(), device).unwrap();

    // Ballot 1: Alice + Yes  → Cast
    let sb1 = mediator
        .encrypt_and_cast(&make_ballot("ballot-1", "sel-alice", "sel-yes"))
        .unwrap();
    // Ballot 2: Bob + No     → Cast
    let sb2 = mediator
        .encrypt_and_cast(&make_ballot("ballot-2", "sel-bob", "sel-no"))
        .unwrap();
    // Ballot 3: Alice + Yes  → Cast
    let sb3 = mediator
        .encrypt_and_cast(&make_ballot("ballot-3", "sel-alice", "sel-yes"))
        .unwrap();
    // Ballot 4: Charlie + No → Spoiled (does not count in tally)
    let sb4 = mediator
        .encrypt_and_spoil(&make_ballot("ballot-4", "sel-charlie", "sel-no"))
        .unwrap();
    // Ballot 5: Bob + Yes    → Cast
    let sb5 = mediator
        .encrypt_and_cast(&make_ballot("ballot-5", "sel-bob", "sel-yes"))
        .unwrap();

    // ── Step 6: Verify submission states and nonce clearing ──────────────────
    assert_eq!(sb1.state, BallotBoxState::Cast,    "ballot-1 must be Cast");
    assert_eq!(sb2.state, BallotBoxState::Cast,    "ballot-2 must be Cast");
    assert_eq!(sb3.state, BallotBoxState::Cast,    "ballot-3 must be Cast");
    assert_eq!(sb4.state, BallotBoxState::Spoiled, "ballot-4 must be Spoiled");
    assert_eq!(sb5.state, BallotBoxState::Cast,    "ballot-5 must be Cast");

    // Nonces must be stripped after submission.
    assert!(sb1.nonce.is_none(), "cast ballot nonce must be cleared");
    assert!(sb4.nonce.is_none(), "spoiled ballot nonce must be cleared");

    // Contest nonces must also be cleared.
    for contest in &sb1.contests {
        assert!(contest.nonce.is_none(), "contest nonce must be cleared");
    }

    // Verify ballot encryption proofs for cast ballots.
    for sb in &[&sb1, &sb2, &sb3, &sb5] {
        assert!(
            sb.is_valid_encryption(
                &context.manifest_hash,
                &context.elgamal_public_key,
                &context.extended_base_hash
            ),
            "ballot {} encryption proof invalid",
            sb.object_id
        );
    }

    // ── Step 7: Build homomorphic tally from cast ballots only ───────────────
    let cast_ballots = [&sb1, &sb2, &sb3, &sb5];
    let tally = accumulate_tally(&cast_ballots);

    assert!(tally.contains_key("contest-president"), "tally must have president contest");
    assert!(tally.contains_key("contest-prop1"),     "tally must have prop1 contest");
    assert_eq!(tally["contest-president"].len(), 3,  "president must have 3 selections");
    assert_eq!(tally["contest-prop1"].len(), 2,      "prop1 must have 2 selections");

    // ── Step 8: Threshold decryption (guardians 1 and 2, quorum = 2 of 3) ───
    //
    // The combined secret is  s = s_1 + s_2 + s_3  (sum of guardian vote secrets).
    // The combined Shamir share at index j is  F(j) = Σ_i f_i(j).
    //
    // Lagrange interpolation with quorum {1, 2} evaluates at x=0:
    //   w_1 · F(1) + w_2 · F(2) = F(0) = s
    //
    // Hence  A^{F(1)^w_1} · A^{F(2)^w_2} = A^s = K^r  and  B / K^r = g^m.

    // — Guardian 1 computes F(1) = f_1(1) + f_2(1) + f_3(1) ——————————
    let f_1_at_1 = compute_polynomial_coordinate(1, &coeff1.coefficients); // own poly
    let f_2_at_1 = decrypt_share(
        &share_2_for_1,
        &key_set1.comm_key_pair.secret_key,
        1,
    )
    .unwrap()
    .value;
    let f_3_at_1 = decrypt_share(
        &share_3_for_1,
        &key_set1.comm_key_pair.secret_key,
        1,
    )
    .unwrap()
    .value;
    let combined_secret_1 = add_mod_q(&add_mod_q(&f_1_at_1, &f_2_at_1), &f_3_at_1);

    // — Guardian 2 computes F(2) = f_1(2) + f_2(2) + f_3(2) ——————————
    let f_1_at_2 = decrypt_share(
        &share_1_for_2,
        &key_set2.comm_key_pair.secret_key,
        2,
    )
    .unwrap()
    .value;
    let f_2_at_2 = compute_polynomial_coordinate(2, &coeff2.coefficients); // own poly
    let f_3_at_2 = decrypt_share(
        &share_3_for_2,
        &key_set2.comm_key_pair.secret_key,
        2,
    )
    .unwrap()
    .value;
    let combined_secret_2 = add_mod_q(&add_mod_q(&f_1_at_2, &f_2_at_2), &f_3_at_2);

    // Public keys corresponding to the combined Shamir shares.
    let combined_pub_key_1 = g_pow(&combined_secret_1);
    let combined_pub_key_2 = g_pow(&combined_secret_2);

    // Lagrange coefficients for quorum {1, 2}.
    let w_1 = compute_lagrange_coefficient(1, &[1, 2]).unwrap(); // = 2
    let w_2 = compute_lagrange_coefficient(2, &[1, 2]).unwrap(); // = Q-1

    // Build partial-decryption share sets for each participating guardian.
    let mut tally_share_1 = TallyDecryptionShare::new("guardian-1".to_string());
    let mut tally_share_2 = TallyDecryptionShare::new("guardian-2".to_string());

    for (contest_id, sel_map) in &tally {
        for (sel_id, ct) in sel_map {
            // Guardian 1 partially decrypts with its combined Shamir share.
            let (share_1_dec, proof_1) = compute_decryption_share(&combined_secret_1, ct);
            // Guardian 2 partially decrypts with its combined Shamir share.
            let (share_2_dec, proof_2) = compute_decryption_share(&combined_secret_2, ct);

            // ── Step 9: Verify all decryption proofs ──────────────────────
            assert!(
                verify_decryption_proof(&proof_1, &ct.pad, &combined_pub_key_1, &share_1_dec),
                "G1 decryption proof invalid for {}/{}", contest_id, sel_id
            );
            assert!(
                verify_decryption_proof(&proof_2, &ct.pad, &combined_pub_key_2, &share_2_dec),
                "G2 decryption proof invalid for {}/{}", contest_id, sel_id
            );

            tally_share_1.insert(
                contest_id,
                sel_id,
                PartialDecryption::new("guardian-1".to_string(), share_1_dec, proof_1),
            );
            tally_share_2.insert(
                contest_id,
                sel_id,
                PartialDecryption::new("guardian-2".to_string(), share_2_dec, proof_2),
            );
        }
    }

    // Lagrange coefficient map keyed by guardian ID.
    let mut lagrange = HashMap::new();
    lagrange.insert("guardian-1".to_string(), w_1);
    lagrange.insert("guardian-2".to_string(), w_2);

    let result = decrypt_tally_with_shares(
        &tally,
        &[tally_share_1, tally_share_2],
        &lagrange,
    )
    .unwrap();

    // ── Step 10: Verify tally against expected vote counts ───────────────────
    //
    // Cast ballots: 1(Alice+Yes), 2(Bob+No), 3(Alice+Yes), 5(Bob+Yes)
    // Expected president : Alice=2, Bob=2, Charlie=0
    // Expected prop1     : Yes=3,  No=1
    let pres = result.get("contest-president").expect("missing president contest");
    let prop  = result.get("contest-prop1").expect("missing prop1 contest");

    assert_eq!(pres["sel-alice"],   2, "Alice should have 2 votes");
    assert_eq!(pres["sel-bob"],     2, "Bob should have 2 votes");
    assert_eq!(pres["sel-charlie"], 0, "Charlie should have 0 votes (ballot spoiled)");
    assert_eq!(prop["sel-yes"],     3, "Yes should have 3 votes");
    assert_eq!(prop["sel-no"],      1, "No should have 1 vote");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 2: Key ceremony share exchange
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify the full key-ceremony share exchange between 3 guardians:
/// - All 6 shares generated and verified successfully.
/// - All Schnorr proofs for every polynomial coefficient pass.
#[test]
fn test_key_ceremony_share_exchange() {
    let quorum = 2u32;
    let ph = compute_parameter_hash().unwrap();

    let (ks1, c1, pk1) = generate_election_key_pair("g1", 1, quorum, &ElementModQ::from_u64(10)).unwrap();
    let (ks2, c2, pk2) = generate_election_key_pair("g2", 2, quorum, &ElementModQ::from_u64(20)).unwrap();
    let (ks3, c3, pk3) = generate_election_key_pair("g3", 3, quorum, &ElementModQ::from_u64(30)).unwrap();

    // Verify all Schnorr proofs for every coefficient.
    let (vp1, dp1) = generate_guardian_proofs(&ks1, &ph, &ElementModQ::from_u64(11)).unwrap();
    let (vp2, dp2) = generate_guardian_proofs(&ks2, &ph, &ElementModQ::from_u64(22)).unwrap();
    let (vp3, dp3) = generate_guardian_proofs(&ks3, &ph, &ElementModQ::from_u64(33)).unwrap();

    for p in vp1.proofs.iter().chain(dp1.proofs.iter()) {
        assert!(verify_schnorr_proof(p, &ph), "G1 Schnorr proof failed");
    }
    for p in vp2.proofs.iter().chain(dp2.proofs.iter()) {
        assert!(verify_schnorr_proof(p, &ph), "G2 Schnorr proof failed");
    }
    for p in vp3.proofs.iter().chain(dp3.proofs.iter()) {
        assert!(verify_schnorr_proof(p, &ph), "G3 Schnorr proof failed");
    }

    // Generate all 6 pairwise shares.
    let s12 = generate_election_partial_key_backup("g1", "g2", 2, &c1.coefficients, &ks2.comm_key_pair.public_key).unwrap();
    let s13 = generate_election_partial_key_backup("g1", "g3", 3, &c1.coefficients, &ks3.comm_key_pair.public_key).unwrap();
    let s21 = generate_election_partial_key_backup("g2", "g1", 1, &c2.coefficients, &ks1.comm_key_pair.public_key).unwrap();
    let s23 = generate_election_partial_key_backup("g2", "g3", 3, &c2.coefficients, &ks3.comm_key_pair.public_key).unwrap();
    let s31 = generate_election_partial_key_backup("g3", "g1", 1, &c3.coefficients, &ks1.comm_key_pair.public_key).unwrap();
    let s32 = generate_election_partial_key_backup("g3", "g2", 2, &c3.coefficients, &ks2.comm_key_pair.public_key).unwrap();

    // Verify all 6 shares against the sender's vote commitments.
    assert!(verify_election_partial_key_backup(&s12, &ks2.comm_key_pair.secret_key, 2, &pk1.vote_commitments).unwrap(), "s12 invalid");
    assert!(verify_election_partial_key_backup(&s13, &ks3.comm_key_pair.secret_key, 3, &pk1.vote_commitments).unwrap(), "s13 invalid");
    assert!(verify_election_partial_key_backup(&s21, &ks1.comm_key_pair.secret_key, 1, &pk2.vote_commitments).unwrap(), "s21 invalid");
    assert!(verify_election_partial_key_backup(&s23, &ks3.comm_key_pair.secret_key, 3, &pk2.vote_commitments).unwrap(), "s23 invalid");
    assert!(verify_election_partial_key_backup(&s31, &ks1.comm_key_pair.secret_key, 1, &pk3.vote_commitments).unwrap(), "s31 invalid");
    assert!(verify_election_partial_key_backup(&s32, &ks2.comm_key_pair.secret_key, 2, &pk3.vote_commitments).unwrap(), "s32 invalid");

    // Confirm joint key equals g^(s1+s2+s3).
    let joint = compute_joint_key(&[
        ks1.vote_key_pair.public_key.clone(),
        ks2.vote_key_pair.public_key.clone(),
        ks3.vote_key_pair.public_key.clone(),
    ]);
    let s_combined = electionguard_core2::group::add_mod_q(
        &electionguard_core2::group::add_mod_q(
            &ks1.vote_key_pair.secret_key,
            &ks2.vote_key_pair.secret_key,
        ),
        &ks3.vote_key_pair.secret_key,
    );
    assert_eq!(joint, g_pow(&s_combined), "joint key must equal g^(s1+s2+s3)");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 3: Ballot encryption and submission
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that:
/// - Ballots encrypt correctly via EncryptionMediator.
/// - Cast/spoiled submission strips all nonces.
/// - Successive ballots have distinct confirmation codes.
/// - Encryption proofs validate.
#[test]
fn test_ballot_encryption_and_cast() {
    let manifest = make_manifest();
    let manifest_hash = manifest.crypto_hash().unwrap();
    let internal_manifest = InternalManifest::from_manifest(&manifest).unwrap();

    // Simple single-key context (not full ceremony).
    let secret = ElementModQ::from_u64(42);
    let public_key = g_pow(&secret);
    let data_secret = ElementModQ::from_u64(43);
    let data_key = g_pow(&data_secret);

    let context = CiphertextElectionContext::new(
        1,
        1,
        public_key,
        data_key,
        ElementModQ::from_u64(0),
        manifest_hash,
    )
    .unwrap();

    let device = EncryptionDevice::new(1, 2, 3, "booth-1");
    let mut mediator = EncryptionMediator::new(internal_manifest, context.clone(), device).unwrap();

    // Encrypt two ballots and check confirmation codes are distinct.
    let cb1 = mediator.encrypt(&make_ballot("b1", "sel-alice", "sel-yes")).unwrap();
    let cb2 = mediator.encrypt(&make_ballot("b2", "sel-bob",   "sel-no")).unwrap();
    assert_ne!(cb1.ballot_code, cb2.ballot_code, "distinct ballots must have distinct codes");
    assert_eq!(mediator.ballot_count, 2);

    // Nonces are present before submission.
    assert!(cb1.nonce.is_some(), "ciphertext ballot must have nonce before submission");

    // Cast via SubmittedBallot::from_ciphertext — nonces must be cleared.
    let sb_cast =
        SubmittedBallot::from_ciphertext(cb1.clone(), BallotBoxState::Cast);
    assert_eq!(sb_cast.state, BallotBoxState::Cast);
    assert!(sb_cast.nonce.is_none(), "cast ballot must have no nonce");
    for c in &sb_cast.contests {
        assert!(c.nonce.is_none(), "cast contest must have no nonce");
        for sel in &c.selections {
            assert!(sel.nonce.is_none(), "cast selection must have no nonce");
        }
    }

    // Spoil via mediator helper.
    let sb_spoil = mediator
        .encrypt_and_spoil(&make_ballot("b3", "sel-charlie", "sel-yes"))
        .unwrap();
    assert_eq!(sb_spoil.state, BallotBoxState::Spoiled);
    assert!(sb_spoil.nonce.is_none());

    // Verify encryption proofs for the cast ballot (ciphertext still available).
    assert!(
        sb_cast.is_valid_encryption(
            &context.manifest_hash,
            &context.elgamal_public_key,
            &context.extended_base_hash,
        ),
        "cast ballot encryption proof must be valid"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 4: Homomorphic tally accumulation
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that homomorphic accumulation over cast ballot ciphertexts yields a
/// ciphertext that decrypts to the correct vote count.
///
/// Setup: single guardian, no threshold (Lagrange coefficient = 1).
#[test]
fn test_homomorphic_tally() {
    // Single-guardian election key.
    let secret = ElementModQ::from_u64(17);
    let public_key = g_pow(&secret);

    // Encrypt individual vote selections (vote ∈ {0, 1}).
    let nonce_a1 = ElementModQ::from_u64(2);
    let nonce_a2 = ElementModQ::from_u64(3);
    let nonce_b1 = ElementModQ::from_u64(5);

    // Two votes for selection A and one for selection B.
    let ct_a1 = elgamal_encrypt(1, &nonce_a1, &public_key); // vote for A (ballot 1)
    let ct_a2 = elgamal_encrypt(1, &nonce_a2, &public_key); // vote for A (ballot 3)
    let ct_b1 = elgamal_encrypt(1, &nonce_b1, &public_key); // vote for B (ballot 2)

    // Also encrypt the "non-votes" for the other selection (0 votes).
    let ct_nota1 = elgamal_encrypt(0, &ElementModQ::from_u64(6), &public_key);
    let ct_nota2 = elgamal_encrypt(0, &ElementModQ::from_u64(7), &public_key);
    let ct_notb1 = elgamal_encrypt(0, &ElementModQ::from_u64(8), &public_key);

    // Accumulate selection A across the 3 ballots → should encrypt 2.
    let tally_a = elgamal_accumulate(&[&ct_a1, &ct_a2, &ct_notb1]);
    // Accumulate selection B across the 3 ballots → should encrypt 1.
    let tally_b = elgamal_accumulate(&[&ct_nota1, &ct_nota2, &ct_b1]);

    // Decrypt using single guardian (Lagrange = 1, no threshold needed).
    // M = A^secret  (the full decryption factor = K^r)
    let dlog = DiscreteLogTable::with_generator(20); // small table is enough

    let decrypt_count = |ct: &ElGamalCiphertext| -> u64 {
        use electionguard_core2::group::pow_mod_p;
        let m = pow_mod_p(&ct.pad, &secret); // K^r = A^s (single guardian)
        let g_m = div_mod_p(&ct.data, &m).unwrap();
        dlog.solve(&g_m).unwrap()
    };

    assert_eq!(decrypt_count(&tally_a), 2, "tally_a must decrypt to 2");
    assert_eq!(decrypt_count(&tally_b), 1, "tally_b must decrypt to 1");

    // Verify that accumulating the identity twice leaves the ciphertext unchanged.
    let identity = ElGamalCiphertext {
        pad: ElementModP::one().clone(),
        data: ElementModP::one().clone(),
    };
    let acc_with_zero = elgamal_accumulate(&[&ct_a1, &identity]);
    assert_eq!(decrypt_count(&acc_with_zero), 1, "adding identity must not change the count");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 5: Threshold decryption (2-of-3 guardians)
// ═══════════════════════════════════════════════════════════════════════════════

/// Demonstrate that a ciphertext encrypted under the joint election key can be
/// decrypted using exactly 2 of 3 guardians (Shamir secret sharing + Lagrange).
///
/// Threshold math (k=2, quorum = {1, 2}):
///   F(j) = Σ_i f_i(j)        combined Shamir share at index j
///   w_1  = 2,  w_2 = Q−1     Lagrange coefficients for quorum {1, 2}
///   w_1·F(1) + w_2·F(2) = F(0) = s₁+s₂+s₃ = s   (combined secret)
///   M = A^{F(1)}^{w_1} · A^{F(2)}^{w_2} = A^s = K^r
#[test]
fn test_threshold_decryption_2_of_3() {
    let quorum = 2u32;

    // Set up 3 guardians with deterministic keys.
    let (ks1, c1, _) = generate_election_key_pair("g1", 1, quorum, &ElementModQ::from_u64(500)).unwrap();
    let (ks2, c2, _) = generate_election_key_pair("g2", 2, quorum, &ElementModQ::from_u64(600)).unwrap();
    let (ks3, c3, _) = generate_election_key_pair("g3", 3, quorum, &ElementModQ::from_u64(700)).unwrap();

    // Compute joint election key K = K_1 · K_2 · K_3 = g^(s1+s2+s3).
    let joint_key = compute_joint_key(&[
        ks1.vote_key_pair.public_key.clone(),
        ks2.vote_key_pair.public_key.clone(),
        ks3.vote_key_pair.public_key.clone(),
    ]);

    // Exchange shares so guardians {1, 2} can reconstruct the full secret.
    let s21 = generate_election_partial_key_backup("g2", "g1", 1, &c2.coefficients, &ks1.comm_key_pair.public_key).unwrap();
    let s31 = generate_election_partial_key_backup("g3", "g1", 1, &c3.coefficients, &ks1.comm_key_pair.public_key).unwrap();
    let s12 = generate_election_partial_key_backup("g1", "g2", 2, &c1.coefficients, &ks2.comm_key_pair.public_key).unwrap();
    let s32 = generate_election_partial_key_backup("g3", "g2", 2, &c3.coefficients, &ks2.comm_key_pair.public_key).unwrap();

    // Encrypt a test plaintext under the joint key.
    let plaintext: u64 = 7;
    let nonce = ElementModQ::from_u64(99);
    let ct = elgamal_encrypt(plaintext, &nonce, &joint_key);

    // — Guardian 1 computes combined Shamir share F(1) ——
    let f1_at_1 = compute_polynomial_coordinate(1, &c1.coefficients);
    let f2_at_1 = decrypt_share(&s21, &ks1.comm_key_pair.secret_key, 1).unwrap().value;
    let f3_at_1 = decrypt_share(&s31, &ks1.comm_key_pair.secret_key, 1).unwrap().value;
    let combined_1 = add_mod_q(&add_mod_q(&f1_at_1, &f2_at_1), &f3_at_1);

    // — Guardian 2 computes combined Shamir share F(2) ——
    let f1_at_2 = decrypt_share(&s12, &ks2.comm_key_pair.secret_key, 2).unwrap().value;
    let f2_at_2 = compute_polynomial_coordinate(2, &c2.coefficients);
    let f3_at_2 = decrypt_share(&s32, &ks2.comm_key_pair.secret_key, 2).unwrap().value;
    let combined_2 = add_mod_q(&add_mod_q(&f1_at_2, &f2_at_2), &f3_at_2);

    // Partial decryptions: M_1 = A^{F(1)}, M_2 = A^{F(2)}.
    let (m_1, proof_1) = compute_decryption_share(&combined_1, &ct);
    let (m_2, proof_2) = compute_decryption_share(&combined_2, &ct);

    // Verify both proofs.
    let pub_1 = g_pow(&combined_1);
    let pub_2 = g_pow(&combined_2);
    assert!(verify_decryption_proof(&proof_1, &ct.pad, &pub_1, &m_1), "G1 proof invalid");
    assert!(verify_decryption_proof(&proof_2, &ct.pad, &pub_2, &m_2), "G2 proof invalid");

    // Lagrange coefficients for quorum {1, 2}: w_1=2, w_2=Q-1.
    let w_1 = compute_lagrange_coefficient(1, &[1, 2]).unwrap();
    let w_2 = compute_lagrange_coefficient(2, &[1, 2]).unwrap();

    // Combined decryption factor M = M_1^{w_1} · M_2^{w_2} = A^s = K^r.
    let combined_m = combine_partial_decryptions(&[&m_1, &m_2], &[&w_1, &w_2]);

    // Recover g^m = B / M.
    let g_m = div_mod_p(&ct.data, &combined_m).unwrap();

    // Solve discrete log to get plaintext m.
    let dlog = DiscreteLogTable::with_generator(20);
    let recovered = dlog.solve(&g_m).unwrap();

    assert_eq!(
        recovered, plaintext,
        "2-of-3 threshold decryption must recover the plaintext"
    );
}
