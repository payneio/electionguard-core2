//! Integration tests for ballot types and ballot box state transitions.
//!
//! Tests:
//! 1. PlaintextBallot JSON deserialization.
//! 2. PlaintextBallotContest validation.
//! 3. BallotBoxState transitions via cast() and spoil().
//! 4. SubmittedBallot strips nonces.
//! 5. BallotBoxState serde round-trip.
//! 6. CiphertextBallot JSON round-trip.

use electionguard_core2::{
    ballot::{
        BallotBoxState, CiphertextBallot, CiphertextBallotContest, CiphertextBallotSelection,
        PlaintextBallot, PlaintextBallotContest, PlaintextBallotSelection, SubmittedBallot,
    },
    elgamal::{elgamal_encrypt, ElGamalCiphertext},
    proof::ranged::RangedChaumPedersenProof,
    ElementModP, ElementModQ,
};

// ── Helpers ────────────────────────────────────────────────────────────────

fn dummy_q(n: u64) -> ElementModQ {
    ElementModQ::from_u64(n)
}

fn dummy_key() -> ElementModP {
    ElementModP::g().clone()
}

fn stub_proof() -> RangedChaumPedersenProof {
    RangedChaumPedersenProof {
        range_limit: 0,
        individual_proofs: vec![],
        challenge: dummy_q(0),
    }
}

fn dummy_ct() -> ElGamalCiphertext {
    elgamal_encrypt(0, &dummy_q(5), &dummy_key())
}

fn dummy_selection(object_id: &str, seq: u64, _vote: u64) -> CiphertextBallotSelection {
    CiphertextBallotSelection {
        object_id: object_id.to_string(),
        sequence_order: seq,
        description_hash: dummy_q(7),
        ciphertext: dummy_ct(),
        is_placeholder: false,
        nonce: Some(dummy_q(seq + 10)),
        crypto_hash: dummy_q(0),
        proof: stub_proof(),
        extended_data: None,
    }
}

fn dummy_contest(object_id: &str) -> CiphertextBallotContest {
    CiphertextBallotContest {
        object_id: object_id.to_string(),
        sequence_order: 1,
        description_hash: dummy_q(3),
        selections: vec![dummy_selection("sel-1", 1, 1), dummy_selection("sel-2", 2, 0)],
        nonce: Some(dummy_q(99)),
        ciphertext_accumulation: dummy_ct(),
        crypto_hash: dummy_q(0),
        proof: stub_proof(),
        hashed_elgamal: None,
    }
}

fn dummy_ciphertext_ballot(state: BallotBoxState) -> CiphertextBallot {
    CiphertextBallot {
        object_id: "ballot-1".to_string(),
        style_id: "style-1".to_string(),
        manifest_hash: dummy_q(1),
        ballot_code_seed: dummy_q(2),
        contests: vec![dummy_contest("contest-1")],
        ballot_code: dummy_q(3),
        timestamp: 1_700_000_000,
        nonce: Some(dummy_q(42)),
        crypto_hash: dummy_q(4),
        state,
        ballot_id: None,
        nonce_ciphertext: None,
        chaining_field: None,
        selection_encryption_id: None,
    }
}

// ── PlaintextBallot tests ──────────────────────────────────────────────────

#[test]
fn plaintext_ballot_json_round_trip() {
    let json = r#"{
        "object_id": "ballot-A",
        "style_id": "style-1",
        "contests": [
            {
                "object_id": "contest-1",
                "selections": [
                    {"object_id": "sel-A", "vote": 1},
                    {"object_id": "sel-B", "vote": 0}
                ]
            }
        ]
    }"#;

    let ballot = PlaintextBallot::from_json(json).unwrap();
    assert_eq!(ballot.object_id, "ballot-A");
    assert_eq!(ballot.style_id, "style-1");
    assert_eq!(ballot.contests.len(), 1);
    assert_eq!(ballot.contests[0].object_id, "contest-1");
    assert_eq!(ballot.contests[0].selections.len(), 2);
    assert_eq!(ballot.contests[0].selections[0].vote, 1);
    assert_eq!(ballot.contests[0].selections[1].vote, 0);

    // Round-trip.
    let json2 = ballot.to_json().unwrap();
    let ballot2 = PlaintextBallot::from_json(&json2).unwrap();
    assert_eq!(ballot.object_id, ballot2.object_id);
    assert_eq!(ballot.contests.len(), ballot2.contests.len());
}

#[test]
fn plaintext_ballot_defaults_for_optional_fields() {
    let json = r#"{
        "object_id": "b1",
        "style_id": "s1",
        "contests": []
    }"#;
    let ballot = PlaintextBallot::from_json(json).unwrap();
    assert!(ballot.contests.is_empty());
}

#[test]
fn plaintext_ballot_invalid_json_returns_error() {
    let result = PlaintextBallot::from_json("{not valid json}");
    assert!(result.is_err(), "invalid JSON must return an error");
}

// ── PlaintextBallotContest validation ──────────────────────────────────────

#[test]
fn contest_valid_one_of_m() {
    let contest = PlaintextBallotContest {
        object_id: "c1".to_string(),
        selections: vec![
            PlaintextBallotSelection {
                object_id: "s1".to_string(),
                vote: 1,
                is_placeholder_selection: false,
                extended_data: None,
            },
            PlaintextBallotSelection {
                object_id: "s2".to_string(),
                vote: 0,
                is_placeholder_selection: false,
                extended_data: None,
            },
        ],
    };
    assert!(contest.is_valid("c1", 2, 1, Some(1)));
}

#[test]
fn contest_invalid_wrong_id() {
    let contest = PlaintextBallotContest {
        object_id: "c1".to_string(),
        selections: vec![PlaintextBallotSelection {
            object_id: "s1".to_string(),
            vote: 1,
            is_placeholder_selection: false,
            extended_data: None,
        }],
    };
    assert!(!contest.is_valid("wrong-id", 1, 1, Some(1)));
}

#[test]
fn contest_invalid_wrong_selection_count() {
    let contest = PlaintextBallotContest {
        object_id: "c1".to_string(),
        selections: vec![PlaintextBallotSelection {
            object_id: "s1".to_string(),
            vote: 1,
            is_placeholder_selection: false,
            extended_data: None,
        }],
    };
    // Expects 2 selections but only 1 present.
    assert!(!contest.is_valid("c1", 2, 1, Some(1)));
}

#[test]
fn contest_invalid_overvote() {
    let contest = PlaintextBallotContest {
        object_id: "c1".to_string(),
        selections: vec![
            PlaintextBallotSelection {
                object_id: "s1".to_string(),
                vote: 1,
                is_placeholder_selection: false,
                extended_data: None,
            },
            PlaintextBallotSelection {
                object_id: "s2".to_string(),
                vote: 1,
                is_placeholder_selection: false,
                extended_data: None,
            },
        ],
    };
    // max 1 vote but total = 2 → overvote.
    assert!(!contest.is_valid("c1", 2, 1, Some(1)));
}

#[test]
fn contest_valid_n_of_m() {
    let contest = PlaintextBallotContest {
        object_id: "c1".to_string(),
        selections: vec![
            PlaintextBallotSelection {
                object_id: "s1".to_string(),
                vote: 1,
                is_placeholder_selection: false,
                extended_data: None,
            },
            PlaintextBallotSelection {
                object_id: "s2".to_string(),
                vote: 1,
                is_placeholder_selection: false,
                extended_data: None,
            },
            PlaintextBallotSelection {
                object_id: "s3".to_string(),
                vote: 0,
                is_placeholder_selection: false,
                extended_data: None,
            },
        ],
    };
    // 2-of-3: votes_allowed = 2, number_elected = 2.
    assert!(contest.is_valid("c1", 3, 2, Some(2)));
}

// ── BallotBoxState serialization ───────────────────────────────────────────

#[test]
fn ballot_box_state_serde_all_variants() {
    let cases = [
        (BallotBoxState::Unknown, "\"unknown\""),
        (BallotBoxState::Cast, "\"cast\""),
        (BallotBoxState::Spoiled, "\"spoiled\""),
        (BallotBoxState::Challenged, "\"challenged\""),
    ];
    for (state, expected) in &cases {
        let json = serde_json::to_string(state).unwrap();
        assert_eq!(&json, expected, "state {:?} should serialize to {}", state, expected);
        let back: BallotBoxState = serde_json::from_str(expected).unwrap();
        assert_eq!(&back, state, "deserialized state should match");
    }
}

#[test]
fn ballot_box_state_default_is_unknown() {
    assert_eq!(BallotBoxState::default(), BallotBoxState::Unknown);
}

// ── BallotBoxState transitions ─────────────────────────────────────────────

#[test]
fn cast_sets_state_and_strips_nonces() {
    let mut ballot = dummy_ciphertext_ballot(BallotBoxState::Unknown);
    assert!(ballot.nonce.is_some());
    assert!(ballot.contests[0].nonce.is_some());

    ballot.cast();

    assert_eq!(ballot.state, BallotBoxState::Cast);
    assert!(ballot.nonce.is_none(), "ballot nonce must be stripped after cast()");
    assert!(ballot.contests[0].nonce.is_none(), "contest nonce must be stripped after cast()");
    assert!(
        ballot.contests[0].selections[0].nonce.is_none(),
        "selection nonce must be stripped after cast()"
    );
}

#[test]
fn spoil_sets_state_and_strips_nonces() {
    let mut ballot = dummy_ciphertext_ballot(BallotBoxState::Unknown);
    ballot.spoil();
    assert_eq!(ballot.state, BallotBoxState::Spoiled);
    assert!(ballot.nonce.is_none());
    assert!(ballot.contests[0].nonce.is_none());
}

#[test]
fn submitted_ballot_from_ciphertext_cast() {
    let ballot = dummy_ciphertext_ballot(BallotBoxState::Unknown);
    let submitted = SubmittedBallot::from_ciphertext(ballot, BallotBoxState::Cast);
    assert_eq!(submitted.state, BallotBoxState::Cast);
    assert!(submitted.nonce.is_none());
    assert!(submitted.contests[0].nonce.is_none());
    assert!(submitted.contests[0].selections[0].nonce.is_none());
}

#[test]
fn submitted_ballot_from_ciphertext_spoiled() {
    let ballot = dummy_ciphertext_ballot(BallotBoxState::Unknown);
    let submitted = SubmittedBallot::from_ciphertext(ballot, BallotBoxState::Spoiled);
    assert_eq!(submitted.state, BallotBoxState::Spoiled);
}

#[test]
fn submitted_ballot_from_ciphertext_challenged() {
    let ballot = dummy_ciphertext_ballot(BallotBoxState::Unknown);
    let submitted = SubmittedBallot::from_ciphertext(ballot, BallotBoxState::Challenged);
    assert_eq!(submitted.state, BallotBoxState::Challenged);
}

#[test]
fn submitted_ballot_deref_provides_ballot_access() {
    let ballot = dummy_ciphertext_ballot(BallotBoxState::Unknown);
    let submitted = SubmittedBallot::from_ciphertext(ballot, BallotBoxState::Cast);
    // Deref should expose the inner CiphertextBallot fields.
    assert_eq!(submitted.object_id, "ballot-1");
    assert_eq!(submitted.style_id, "style-1");
    assert_eq!(submitted.contests.len(), 1);
}

// ── CiphertextBallot JSON round-trip ───────────────────────────────────────

#[test]
fn ciphertext_ballot_json_round_trip() {
    // Build and serialize a ballot, then deserialize and verify key fields.
    let ballot = dummy_ciphertext_ballot(BallotBoxState::Cast);
    let json = ballot.to_json().unwrap();
    assert!(!json.is_empty());

    let back = CiphertextBallot::from_json(&json).unwrap();
    assert_eq!(ballot.object_id, back.object_id);
    assert_eq!(ballot.style_id, back.style_id);
    assert_eq!(ballot.timestamp, back.timestamp);
    assert_eq!(ballot.state, back.state);
    assert_eq!(ballot.contests.len(), back.contests.len());
    assert_eq!(
        ballot.contests[0].object_id,
        back.contests[0].object_id
    );
}

#[test]
fn ciphertext_ballot_nonce_omitted_when_none() {
    let mut ballot = dummy_ciphertext_ballot(BallotBoxState::Unknown);
    ballot.cast(); // strips nonce
    let json = ballot.to_json().unwrap();
    assert!(
        !json.contains("\"nonce\""),
        "nonce field must be omitted when None (skip_serializing_if)"
    );
}

#[test]
fn submitted_ballot_json_round_trip() {
    let ballot = dummy_ciphertext_ballot(BallotBoxState::Unknown);
    let submitted = SubmittedBallot::from_ciphertext(ballot, BallotBoxState::Cast);
    let json = submitted.to_json().unwrap();
    let back = SubmittedBallot::from_json(&json).unwrap();
    assert_eq!(submitted.object_id, back.object_id);
    assert_eq!(submitted.state, back.state);
}

// ── PlaintextBallot: is_placeholder_selection filter (line 92) ────────────

#[test]
fn is_valid_skips_placeholder_votes_from_overvote_check() {
    // A placeholder selection with vote=1 must not count towards the overvote limit
    // when real_votes <= max_votes.
    let contest = PlaintextBallotContest {
        object_id: "c1".to_string(),
        selections: vec![
            PlaintextBallotSelection {
                object_id: "real-1".to_string(),
                vote: 1,
                is_placeholder_selection: false,
                extended_data: None,
            },
            PlaintextBallotSelection {
                object_id: "placeholder-1".to_string(),
                vote: 1,
                // Placeholder vote doesn't count against real limit
                is_placeholder_selection: true,
                extended_data: None,
            },
        ],
    };
    // total_votes = 2 (> max_votes=1) so this fails the total-votes check first.
    // We test the placeholder path by making max_votes cover all votes.
    assert!(!contest.is_valid("c1", 2, 2, Some(1)),
        "total_votes(2) > max_votes(1), must be invalid");
    // Now set max_votes=2 → total passes, real_votes=1 <= max_votes=2 → valid
    assert!(contest.is_valid("c1", 2, 2, Some(2)),
        "total_votes=2 <= max_votes=2 and real_votes=1 <= 2, must be valid");
}

#[test]
fn is_valid_real_votes_only_contest() {
    // Contest with only placeholder selections, no real votes
    let contest = PlaintextBallotContest {
        object_id: "c1".to_string(),
        selections: vec![
            PlaintextBallotSelection {
                object_id: "ph-1".to_string(),
                vote: 0,
                is_placeholder_selection: true,
                extended_data: None,
            },
            PlaintextBallotSelection {
                object_id: "ph-2".to_string(),
                vote: 0,
                is_placeholder_selection: true,
                extended_data: None,
            },
        ],
    };
    // real_votes = 0 <= max_votes=1, and total_votes=0 <= 1 → valid
    assert!(contest.is_valid("c1", 2, 1, Some(1)));
}

// ── PlaintextBallot to_json (line 122 map_err always unreachable for valid struct)

#[test]
fn plaintext_ballot_to_json_produces_valid_json() {
    let ballot = PlaintextBallot {
        object_id: "b1".to_string(),
        style_id: "s1".to_string(),
        contests: vec![],
    };
    let json = ballot.to_json().unwrap();
    assert!(json.contains("\"object_id\""));
    assert!(json.contains("b1"));
}

// ── CiphertextBallotSelection::crypto_hash (line 218) ────────────────────

#[test]
fn ciphertext_ballot_selection_crypto_hash_is_deterministic() {
    use electionguard_core2::hash::CryptoHashable;
    let sel = dummy_selection("sel-1", 1, 1);
    let h1 = sel.crypto_hash().unwrap();
    let h2 = sel.crypto_hash().unwrap();
    assert_eq!(h1, h2);
}

// ── CiphertextBallotContest::aggregate_nonce (lines 295, 302, 304) ────────

#[test]
fn contest_aggregate_nonce_with_nonces_present() {
    let contest = dummy_contest("contest-1");
    let agg = contest.aggregate_nonce().unwrap();
    assert!(!agg.is_zero(), "aggregate nonce should be non-zero with real nonces");
}

#[test]
fn contest_aggregate_nonce_fails_when_nonce_cleared() {
    let mut contest = dummy_contest("contest-1");
    // Clear all selection nonces
    for sel in &mut contest.selections {
        sel.nonce = None;
    }
    let result = contest.aggregate_nonce();
    assert!(result.is_err(), "aggregate_nonce must fail when selections have no nonces");
}

// ── CiphertextBallotContest::is_valid_encryption (line 314) ──────────────

#[test]
fn contest_is_valid_encryption_returns_bool() {
    use electionguard_core2::group::{ElementModQ, ElementModP};
    let contest = dummy_contest("contest-1");
    let seed = ElementModQ::from_u64(1);
    let public_key = ElementModP::g().clone();
    let ext_hash = ElementModQ::from_u64(2);
    // The dummy contest won't be a valid encryption but the function must not panic
    let _result = contest.is_valid_encryption(&seed, &public_key, &ext_hash);
}

// ── CiphertextBallot::to_json_with_nonces (line 494) ─────────────────────

#[test]
fn ciphertext_ballot_to_json_with_nonces() {
    let ballot = dummy_ciphertext_ballot(BallotBoxState::Unknown);
    let json_with = ballot.to_json_with_nonces().unwrap();
    let json_plain = ballot.to_json().unwrap();
    // Both should include nonces since the ballot has nonces (Some value)
    assert!(json_with.contains("\"nonce\""), "to_json_with_nonces must include nonces");
    assert_eq!(json_with, json_plain, "with nonces == plain when nonces are present");
}

// ── CiphertextBallot::from_json error path (line 484 map_err) ────────────

#[test]
fn ciphertext_ballot_from_json_invalid_returns_error() {
    let result = CiphertextBallot::from_json("{not valid json at all!}");
    assert!(result.is_err(), "invalid JSON must produce an error");
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("CiphertextBallot::from_json") || err_str.contains("Serialization"),
        "error message must reference the caller"
    );
}

// ── SubmittedBallot::from_json error path (line 542 map_err) ─────────────

#[test]
fn submitted_ballot_from_json_invalid_returns_error() {
    let result = SubmittedBallot::from_json("{{bad json");
    assert!(result.is_err(), "invalid JSON must produce an error");
}

// ── SubmittedBallot::Deref (line 554) ─────────────────────────────────────

#[test]
fn submitted_ballot_deref_exposes_inner_fields() {
    let ballot = dummy_ciphertext_ballot(BallotBoxState::Unknown);
    let submitted = SubmittedBallot::from_ciphertext(ballot.clone(), BallotBoxState::Cast);
    // Deref: submitted.object_id calls Deref::deref()
    assert_eq!(*submitted.object_id, ballot.object_id);
    assert_eq!(submitted.style_id, ballot.style_id);
    assert_eq!(submitted.contests.len(), ballot.contests.len());
}

// ── SubmittedBallot::to_json error-path smoke test ────────────────────────

#[test]
fn submitted_ballot_to_json_produces_valid_json() {
    let ballot = dummy_ciphertext_ballot(BallotBoxState::Unknown);
    let submitted = SubmittedBallot::from_ciphertext(ballot, BallotBoxState::Cast);
    let json = submitted.to_json().unwrap();
    assert!(json.contains("\"object_id\""));
    assert!(json.contains("ballot-1"));
}
