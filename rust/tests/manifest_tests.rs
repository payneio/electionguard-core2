//! Integration tests for manifest types: is_valid, CryptoHashable impls,
//! InternalManifest construction and navigation, and serde error paths.

use electionguard_core2::{
    hash::CryptoHashable,
    manifest::{
        BallotStyle, Candidate, ContestDescription, ContestDescriptionWithPlaceholders,
        GeopoliticalUnit, InternalManifest, Manifest, Party, ReportingUnitType, SelectionDescription,
    },
};

// ── Helpers ───────────────────────────────────────────────────────────────

fn sample_selection(id: &str, seq: u64) -> SelectionDescription {
    SelectionDescription {
        object_id: id.to_string(),
        candidate_id: format!("cand-{}", id),
        sequence_order: seq,
    }
}

fn sample_contest(id: &str, district_id: &str) -> ContestDescription {
    use electionguard_core2::manifest::VoteVariationType;
    ContestDescription {
        object_id: id.to_string(),
        electoral_district_id: district_id.to_string(),
        sequence_order: 1,
        vote_variation: VoteVariationType::OneOfM,
        number_elected: 1,
        votes_allowed: Some(1),
        name: "Test Contest".to_string(),
        ballot_title: None,
        ballot_subtitle: None,
        selections: vec![
            sample_selection("sel-A", 1),
            sample_selection("sel-B", 2),
        ],
        primary_party_ids: vec![],
    }
}

fn sample_ballot_style(id: &str, gp_ids: Vec<&str>) -> BallotStyle {
    BallotStyle {
        object_id: id.to_string(),
        geopolitical_unit_ids: gp_ids.iter().map(|s| s.to_string()).collect(),
        party_ids: vec![],
        image_uri: None,
    }
}

fn sample_manifest() -> Manifest {
    use electionguard_core2::manifest::ElectionType;
    Manifest {
        election_scope_id: "scope-1".to_string(),
        spec_version: "v2.1".to_string(),
        election_type: ElectionType::General,
        start_date: "2024-11-05T00:00:00Z".to_string(),
        end_date: "2024-11-05T23:59:59Z".to_string(),
        geopolitical_units: vec![GeopoliticalUnit {
            object_id: "gp-1".to_string(),
            name: "District 1".to_string(),
            reporting_unit_type: ReportingUnitType::Precinct,
            contact_information: None,
        }],
        parties: vec![Party {
            object_id: "party-A".to_string(),
            name: None,
            abbreviation: None,
            color: None,
            logo_uri: None,
        }],
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
        contests: vec![sample_contest("contest-1", "gp-1")],
        ballot_styles: vec![sample_ballot_style("style-1", vec!["gp-1"])],
        name: None,
        contact_information: None,
    }
}

// ── Manifest::is_valid ────────────────────────────────────────────────────

#[test]
fn manifest_is_valid_returns_true_for_complete_manifest() {
    assert!(sample_manifest().is_valid());
}

#[test]
fn manifest_is_valid_false_for_empty_scope_id() {
    let mut m = sample_manifest();
    m.election_scope_id = String::new();
    assert!(!m.is_valid());
}

#[test]
fn manifest_is_valid_false_for_no_contests() {
    let mut m = sample_manifest();
    m.contests.clear();
    assert!(!m.is_valid());
}

#[test]
fn manifest_is_valid_false_for_no_ballot_styles() {
    let mut m = sample_manifest();
    m.ballot_styles.clear();
    assert!(!m.is_valid());
}

// ── Manifest JSON serde ───────────────────────────────────────────────────

#[test]
fn manifest_json_round_trip() {
    let m = sample_manifest();
    let json = m.to_json().unwrap();
    let m2 = Manifest::from_json(&json).unwrap();
    assert_eq!(m.election_scope_id, m2.election_scope_id);
    assert_eq!(m.contests.len(), m2.contests.len());
    assert_eq!(m.ballot_styles.len(), m2.ballot_styles.len());
}

#[test]
fn manifest_from_json_error_path() {
    let result = Manifest::from_json("{completely invalid json!!");
    assert!(result.is_err());
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("Manifest::from_json") || err_msg.contains("Serialization"),
        "error message should reference Manifest::from_json"
    );
}

// ── ContestDescriptionWithPlaceholders methods (lines 235, 239, 244) ─────

fn make_contest_with_placeholders() -> ContestDescriptionWithPlaceholders {
    ContestDescriptionWithPlaceholders {
        contest: sample_contest("contest-1", "gp-1"),
        placeholder_selections: vec![SelectionDescription {
            object_id: "contest-1-placeholder-3".to_string(),
            candidate_id: "contest-1-placeholder-3".to_string(),
            sequence_order: 3,
        }],
    }
}

#[test]
fn is_placeholder_returns_true_for_placeholder_id() {
    let c = make_contest_with_placeholders();
    assert!(
        c.is_placeholder("contest-1-placeholder-3"),
        "placeholder ID must be recognized"
    );
}

#[test]
fn is_placeholder_returns_false_for_real_selection() {
    let c = make_contest_with_placeholders();
    assert!(!c.is_placeholder("sel-A"), "real selection must not be treated as placeholder");
    assert!(!c.is_placeholder("nonexistent"), "unknown ID must not be treated as placeholder");
}

#[test]
fn selection_for_finds_real_selection() {
    let c = make_contest_with_placeholders();
    let sel = c.selection_for("sel-A").expect("sel-A must be found");
    assert_eq!(sel.object_id, "sel-A");
}

#[test]
fn selection_for_falls_through_to_placeholder() {
    let c = make_contest_with_placeholders();
    // Not in real selections → must find in placeholder_selections (line 244)
    let sel = c.selection_for("contest-1-placeholder-3").expect("placeholder must be found");
    assert_eq!(sel.object_id, "contest-1-placeholder-3");
}

#[test]
fn selection_for_returns_none_for_unknown_id() {
    let c = make_contest_with_placeholders();
    assert!(c.selection_for("does-not-exist").is_none());
}

// ── Sub-type CryptoHashable (lines 337, 379-384, 393-395, 400-402, 407-409) ──

#[test]
fn selection_description_crypto_hash_is_deterministic() {
    let sel = sample_selection("sel-A", 1);
    let h1 = sel.crypto_hash().unwrap();
    let h2 = sel.crypto_hash().unwrap();
    assert_eq!(h1, h2);
    assert!(!h1.is_zero());
}

#[test]
fn geopolitical_unit_crypto_hash_is_deterministic() {
    let gp = GeopoliticalUnit {
        object_id: "gp-1".to_string(),
        name: "District 1".to_string(),
        reporting_unit_type: ReportingUnitType::Precinct,
        contact_information: None,
    };
    let h1 = gp.crypto_hash().unwrap();
    let h2 = gp.crypto_hash().unwrap();
    assert_eq!(h1, h2);
    assert!(!h1.is_zero());
}

#[test]
fn ballot_style_crypto_hash_is_deterministic() {
    let bs = sample_ballot_style("style-1", vec!["gp-1"]);
    let h1 = bs.crypto_hash().unwrap();
    let h2 = bs.crypto_hash().unwrap();
    assert_eq!(h1, h2);
    assert!(!h1.is_zero());
}

#[test]
fn party_crypto_hash_is_deterministic() {
    let p = Party {
        object_id: "party-A".to_string(),
        name: None,
        abbreviation: None,
        color: None,
        logo_uri: None,
    };
    let h1 = p.crypto_hash().unwrap();
    let h2 = p.crypto_hash().unwrap();
    assert_eq!(h1, h2);
    assert!(!h1.is_zero());
}

#[test]
fn candidate_crypto_hash_is_deterministic() {
    let c = Candidate {
        object_id: "cand-A".to_string(),
        name: None,
        party_id: None,
        image_uri: None,
        is_write_in: false,
    };
    let h1 = c.crypto_hash().unwrap();
    let h2 = c.crypto_hash().unwrap();
    assert_eq!(h1, h2);
    assert!(!h1.is_zero());
}

#[test]
fn contest_description_crypto_hash_with_votes_allowed_none() {
    // Exercises the `if let Some(va)` branch NOT taken when `votes_allowed` is None
    let mut contest = sample_contest("contest-1", "gp-1");
    contest.votes_allowed = None;
    let h = contest.crypto_hash().unwrap();
    assert!(!h.is_zero());
}

// ── InternalManifest methods (lines 484, 487, 493-494, 500, 506) ─────────

#[test]
fn internal_manifest_contests_for_style_unknown_style_returns_empty() {
    let m = sample_manifest();
    let im = InternalManifest::from_manifest(&m).unwrap();
    let contests = im.contests_for_style("no-such-style");
    assert!(contests.is_empty(), "unknown style must return empty list (line 484)");
}

#[test]
fn internal_manifest_contests_for_style_known_style() {
    let m = sample_manifest();
    let im = InternalManifest::from_manifest(&m).unwrap();
    // "style-1" includes "gp-1" which is the electoral_district_id of contest-1
    let contests = im.contests_for_style("style-1");
    assert_eq!(contests.len(), 1, "style-1 should match contest-1 via gp-1 (line 487)");
    assert_eq!(contests[0].contest.object_id, "contest-1");
}

#[test]
fn internal_manifest_ballot_style_found() {
    let m = sample_manifest();
    let im = InternalManifest::from_manifest(&m).unwrap();
    let bs = im.ballot_style("style-1").expect("style-1 must be found");
    assert_eq!(bs.object_id, "style-1");
}

#[test]
fn internal_manifest_ballot_style_not_found() {
    let m = sample_manifest();
    let im = InternalManifest::from_manifest(&m).unwrap();
    assert!(im.ballot_style("no-such-style").is_none());
}

#[test]
fn internal_manifest_json_round_trip() {
    let m = sample_manifest();
    let im = InternalManifest::from_manifest(&m).unwrap();
    let json = im.to_json().unwrap();
    let im2 = InternalManifest::from_json(&json).unwrap();
    assert_eq!(im.manifest_hash, im2.manifest_hash);
    assert_eq!(im.contests.len(), im2.contests.len());
}

#[test]
fn internal_manifest_from_json_error_path() {
    let result = InternalManifest::from_json("{bad json{{");
    assert!(result.is_err());
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("InternalManifest::from_json") || err_msg.contains("Serialization"),
        "error message should reference InternalManifest::from_json"
    );
}

// ── Placeholder generation ─────────────────────────────────────────────────

#[test]
fn generate_placeholder_selection_format() {
    use electionguard_core2::manifest::generate_placeholder_selection;
    let contest = sample_contest("my-contest", "gp-1");
    let ph = generate_placeholder_selection(&contest, 10);
    assert_eq!(ph.object_id, "my-contest-placeholder-10");
    assert_eq!(ph.sequence_order, 10);
}
