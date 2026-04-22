//! Integration tests for election context and parameter hash chain.
//!
//! Tests:
//! 1. Parameter hash computation (H_P) is deterministic and non-zero.
//! 2. Full hash chain H_P → H_B → H_E correctness.
//! 3. `CiphertextElectionContext` JSON serialisation round-trip.
//! 4. Hash changes when inputs change (independence).
//! 5. Manifest validation round-trip.

use electionguard_core2::{
    compute_base_hash, compute_extended_base_hash, compute_parameter_hash,
    election::CiphertextElectionContext,
    manifest::{
        BallotStyle, Candidate, ContestDescription, ElectionType, GeopoliticalUnit, Manifest,
        ReportingUnitType, SelectionDescription, VoteVariationType,
        InternalManifest,
    },
    ElementModP, ElementModQ,
};

// ── Helpers ────────────────────────────────────────────────────────────────

fn dummy_key() -> ElementModP {
    ElementModP::g().clone()
}

fn dummy_q(n: u64) -> ElementModQ {
    ElementModQ::from_u64(n)
}

fn make_context(n: u64, k: u64) -> CiphertextElectionContext {
    let key = dummy_key();
    let mh = dummy_q(1);
    let ch = dummy_q(2);
    CiphertextElectionContext::new(n, k, key.clone(), key, ch, mh).unwrap()
}

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

// ── Parameter hash tests ───────────────────────────────────────────────────

#[test]
fn parameter_hash_is_deterministic() {
    let h1 = compute_parameter_hash().unwrap();
    let h2 = compute_parameter_hash().unwrap();
    assert_eq!(h1, h2, "H_P must be deterministic");
}

#[test]
fn parameter_hash_is_nonzero() {
    let hp = compute_parameter_hash().unwrap();
    assert!(!hp.is_zero(), "H_P must not be zero");
}

#[test]
fn parameter_hash_is_valid_q_element() {
    // Ensure H_P is a valid element (within range) by checking it constructs OK.
    let hp = compute_parameter_hash().unwrap();
    // Re-parse from bytes to confirm it is < Q.
    let bytes = hp.to_bytes_be();
    let reparsed = ElementModQ::from_bytes_be(&bytes).unwrap();
    assert_eq!(hp, reparsed);
}

// ── Base hash tests ────────────────────────────────────────────────────────

#[test]
fn base_hash_deterministic() {
    let hp = compute_parameter_hash().unwrap();
    let mh = dummy_q(1);
    let ch = dummy_q(2);
    let hb1 = compute_base_hash(&hp, 3, 2, &mh, &ch).unwrap();
    let hb2 = compute_base_hash(&hp, 3, 2, &mh, &ch).unwrap();
    assert_eq!(hb1, hb2);
}

#[test]
fn base_hash_distinct_from_parameter_hash() {
    let hp = compute_parameter_hash().unwrap();
    let mh = dummy_q(1);
    let ch = dummy_q(2);
    let hb = compute_base_hash(&hp, 3, 2, &mh, &ch).unwrap();
    assert_ne!(hp, hb, "H_B must be distinct from H_P");
}

#[test]
fn base_hash_changes_with_n() {
    let hp = compute_parameter_hash().unwrap();
    let mh = dummy_q(1);
    let ch = dummy_q(2);
    let hb3 = compute_base_hash(&hp, 3, 2, &mh, &ch).unwrap();
    let hb5 = compute_base_hash(&hp, 5, 2, &mh, &ch).unwrap();
    assert_ne!(hb3, hb5, "changing n must change H_B");
}

#[test]
fn base_hash_changes_with_k() {
    let hp = compute_parameter_hash().unwrap();
    let mh = dummy_q(1);
    let ch = dummy_q(2);
    let hb2 = compute_base_hash(&hp, 3, 2, &mh, &ch).unwrap();
    let hb3 = compute_base_hash(&hp, 3, 3, &mh, &ch).unwrap();
    assert_ne!(hb2, hb3, "changing k must change H_B");
}

#[test]
fn base_hash_changes_with_manifest_hash() {
    let hp = compute_parameter_hash().unwrap();
    let ch = dummy_q(2);
    let hb1 = compute_base_hash(&hp, 3, 2, &dummy_q(1), &ch).unwrap();
    let hb2 = compute_base_hash(&hp, 3, 2, &dummy_q(9), &ch).unwrap();
    assert_ne!(hb1, hb2, "changing H_M must change H_B");
}

#[test]
fn base_hash_changes_with_commitment_hash() {
    let hp = compute_parameter_hash().unwrap();
    let mh = dummy_q(1);
    let hb1 = compute_base_hash(&hp, 3, 2, &mh, &dummy_q(2)).unwrap();
    let hb2 = compute_base_hash(&hp, 3, 2, &mh, &dummy_q(99)).unwrap();
    assert_ne!(hb1, hb2, "changing Ĥ must change H_B");
}

// ── Extended base hash tests ───────────────────────────────────────────────

#[test]
fn extended_base_hash_deterministic() {
    let hp = compute_parameter_hash().unwrap();
    let mh = dummy_q(1);
    let ch = dummy_q(2);
    let hb = compute_base_hash(&hp, 3, 2, &mh, &ch).unwrap();
    let he1 = compute_extended_base_hash(&hb, &ch).unwrap();
    let he2 = compute_extended_base_hash(&hb, &ch).unwrap();
    assert_eq!(he1, he2);
}

#[test]
fn hash_chain_all_distinct() {
    let hp = compute_parameter_hash().unwrap();
    let mh = dummy_q(1);
    let ch = dummy_q(2);
    let hb = compute_base_hash(&hp, 3, 2, &mh, &ch).unwrap();
    let he = compute_extended_base_hash(&hb, &ch).unwrap();
    assert_ne!(hp, hb, "H_P ≠ H_B");
    assert_ne!(hb, he, "H_B ≠ H_E");
    assert_ne!(hp, he, "H_P ≠ H_E");
}

// ── CiphertextElectionContext tests ────────────────────────────────────────

#[test]
fn context_new_computes_correct_hash_chain() {
    let ctx = make_context(3, 2);
    let hp = compute_parameter_hash().unwrap();
    assert_eq!(ctx.parameter_hash, hp, "stored H_P must match standalone function");

    let hb = compute_base_hash(&hp, 3, 2, &ctx.manifest_hash, &ctx.commitment_hash).unwrap();
    assert_eq!(ctx.base_hash, hb, "stored H_B must match standalone function");

    let he = compute_extended_base_hash(&hb, &ctx.commitment_hash).unwrap();
    assert_eq!(ctx.extended_base_hash, he, "stored H_E must match standalone function");
}

#[test]
fn context_rejects_quorum_exceeds_n() {
    let key = dummy_key();
    let result = CiphertextElectionContext::new(2, 3, key.clone(), key, dummy_q(1), dummy_q(2));
    assert!(result.is_err(), "quorum > n must be rejected");
}

#[test]
fn context_rejects_zero_n() {
    let key = dummy_key();
    let result = CiphertextElectionContext::new(0, 0, key.clone(), key, dummy_q(1), dummy_q(2));
    assert!(result.is_err(), "n=0 must be rejected");
}

#[test]
fn context_accepts_quorum_equals_n() {
    let key = dummy_key();
    let result = CiphertextElectionContext::new(3, 3, key.clone(), key, dummy_q(1), dummy_q(2));
    assert!(result.is_ok(), "quorum = n is valid (all-guardian threshold)");
}

#[test]
fn context_json_round_trip() {
    let ctx = make_context(3, 2);
    let json = ctx.to_json().unwrap();
    assert!(!json.is_empty());

    let ctx2 = CiphertextElectionContext::from_json(&json).unwrap();
    assert_eq!(ctx.number_of_guardians, ctx2.number_of_guardians);
    assert_eq!(ctx.quorum, ctx2.quorum);
    assert_eq!(ctx.parameter_hash, ctx2.parameter_hash);
    assert_eq!(ctx.base_hash, ctx2.base_hash);
    assert_eq!(ctx.extended_base_hash, ctx2.extended_base_hash);
    assert_eq!(ctx.manifest_hash, ctx2.manifest_hash);
    assert_eq!(ctx.commitment_hash, ctx2.commitment_hash);
}

#[test]
fn context_extended_hash_changes_with_commitment() {
    let key = dummy_key();
    let mh = dummy_q(1);

    let ctx1 = CiphertextElectionContext::new(3, 2, key.clone(), key.clone(), dummy_q(10), mh.clone()).unwrap();
    let ctx2 = CiphertextElectionContext::new(3, 2, key.clone(), key, dummy_q(20), mh).unwrap();

    assert_ne!(
        ctx1.extended_base_hash, ctx2.extended_base_hash,
        "changing commitment_hash must change H_E"
    );
}

// ── Manifest validation ────────────────────────────────────────────────────

#[test]
fn manifest_is_valid() {
    let m = sample_manifest();
    assert!(m.is_valid(), "sample manifest must be valid");
}

#[test]
fn manifest_invalid_empty_contests() {
    let mut m = sample_manifest();
    m.contests.clear();
    assert!(!m.is_valid(), "manifest with no contests must be invalid");
}

#[test]
fn manifest_invalid_empty_ballot_styles() {
    let mut m = sample_manifest();
    m.ballot_styles.clear();
    assert!(!m.is_valid(), "manifest with no ballot styles must be invalid");
}

#[test]
fn manifest_invalid_empty_scope_id() {
    let mut m = sample_manifest();
    m.election_scope_id.clear();
    assert!(!m.is_valid(), "manifest with empty scope_id must be invalid");
}

#[test]
fn manifest_json_round_trip() {
    let m = sample_manifest();
    let json = m.to_json().unwrap();
    let m2 = Manifest::from_json(&json).unwrap();
    assert_eq!(m.election_scope_id, m2.election_scope_id);
    assert_eq!(m.contests.len(), m2.contests.len());
    assert_eq!(m.contests[0].selections.len(), m2.contests[0].selections.len());
}

#[test]
fn manifest_hash_deterministic() {
    use electionguard_core2::hash::CryptoHashable;
    let m = sample_manifest();
    let h1 = m.crypto_hash().unwrap();
    let h2 = m.crypto_hash().unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn manifest_hash_changes_with_scope_id() {
    use electionguard_core2::hash::CryptoHashable;
    let m1 = sample_manifest();
    let mut m2 = sample_manifest();
    m2.election_scope_id = "different-scope".to_string();
    let h1 = m1.crypto_hash().unwrap();
    let h2 = m2.crypto_hash().unwrap();
    assert_ne!(h1, h2, "manifests with different scope_ids must have different hashes");
    let _ = m1;
}

#[test]
fn internal_manifest_from_manifest() {
    let m = sample_manifest();
    let im = InternalManifest::from_manifest(&m).unwrap();
    assert_eq!(im.contests.len(), 1);
    // number_elected=1 → 1 placeholder
    assert_eq!(im.contests[0].placeholder_selections.len(), 1);
    let ph = &im.contests[0].placeholder_selections[0];
    assert!(ph.object_id.contains("placeholder"), "placeholder object_id must contain 'placeholder'");
    // The manifest_hash stored in InternalManifest must match what we compute directly.
    use electionguard_core2::hash::CryptoHashable;
    assert_eq!(im.manifest_hash, m.crypto_hash().unwrap());
}

#[test]
fn internal_manifest_contests_for_style() {
    let m = sample_manifest();
    let im = InternalManifest::from_manifest(&m).unwrap();
    let contests = im.contests_for_style("style-1");
    assert_eq!(contests.len(), 1);

    let no_contests = im.contests_for_style("non-existent-style");
    assert!(no_contests.is_empty());
}

#[test]
fn internal_manifest_json_round_trip() {
    let m = sample_manifest();
    let im = InternalManifest::from_manifest(&m).unwrap();
    let json = im.to_json().unwrap();
    let im2 = InternalManifest::from_json(&json).unwrap();
    assert_eq!(im.manifest_hash, im2.manifest_hash);
    assert_eq!(im.contests.len(), im2.contests.len());
    assert_eq!(
        im.contests[0].placeholder_selections.len(),
        im2.contests[0].placeholder_selections.len()
    );
}
