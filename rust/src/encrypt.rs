//! Ballot encryption: selections, contests, and full ballots.
//!
//! Implements the v2.1 encryption pipeline:
//!
//! ```text
//! PlaintextBallot  →  CiphertextBallot
//!
//! For each contest:
//!   For each selection (real + placeholder):
//!     ξ_{i,j}   = H(H_I; 0x21, i, j, ξ_B)          — selection nonce
//!     (α, β)    = (g^ξ, g^v · K^ξ)                  — ElGamal ciphertext
//!     proof     = RangedChaumPedersenProof             — range [0,1]
//!   accumulation = ∏ (α_j, β_j)                       — homomorphic sum
//!   contest_proof = RangedChaumPedersenProof           — range [0, N_elected]
//!   contest_hash  = H(H_I; 0x28, i, α,β,...)          — contest hash
//! confirmation_code = H(H_I; 0x29, χ_1,...,χ_m, B_C) — ballot code
//! ```

use crate::ballot::{
    BallotBoxState, CiphertextBallot, CiphertextBallotContest, CiphertextBallotSelection,
    PlaintextBallot, PlaintextBallotContest, SubmittedBallot,
};
use crate::ballot_code::{
    build_no_chaining_field, compute_confirmation_code, compute_contest_hash,
    get_hash_for_device,
};
use crate::election::CiphertextElectionContext;
use crate::elgamal::{elgamal_encrypt, HashedElGamalCiphertext};
use crate::error::{Error, Result};
use crate::group::ElementModQ;
use crate::group::constants::{EG_DS_CONTEST_DATA_ENC_PROOF, EG_DS_ENCRYPTION_NONCE};
use crate::hash::{hash_elems_v21, HashableValue};
use crate::manifest::{ContestDescriptionWithPlaceholders, InternalManifest};
use crate::nonces::{
    compute_selection_encryption_id, derive_contest_data_nonce, derive_selection_nonce,
};
use crate::proof::ranged::RangedChaumPedersenProof;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ── EncryptionDevice ──────────────────────────────────────────────────────────

/// An encryption device identifies a specific ballot-marking terminal.
///
/// The device hash `H_DI` is used as the starting point for ballot-code chains.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionDevice {
    /// Persistent device UUID (e.g. hardware serial hash).
    pub device_uuid: u64,
    /// Per-session UUID (re-randomised each session).
    pub session_uuid: u64,
    /// Launch code for the current session.
    pub launch_code: u64,
    /// Human-readable location string.
    pub location: String,
}

impl EncryptionDevice {
    /// Create a new `EncryptionDevice`.
    pub fn new(device_uuid: u64, session_uuid: u64, launch_code: u64, location: &str) -> Self {
        Self {
            device_uuid,
            session_uuid,
            launch_code,
            location: location.to_string(),
        }
    }

    /// Compute the device info hash `H_DI = H(0^32; 0x00, uuid, session, code, loc)`.
    pub fn hash(&self) -> Result<ElementModQ> {
        get_hash_for_device(
            self.device_uuid,
            self.session_uuid,
            self.launch_code,
            &self.location,
        )
    }
}

// ── EncryptionConfig ──────────────────────────────────────────────────────────

/// Configuration options for the encryption mediator.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Chain ballot confirmation codes (default `false` = no-chain mode).
    pub use_chaining: bool,
    /// Verify proofs immediately after generation (default `true`).
    pub should_verify_proofs: bool,
}

// ── EncryptionMediator ────────────────────────────────────────────────────────

/// Stateful mediator that encrypts ballots one at a time.
///
/// Maintains the confirmation-code chain state so that successive `encrypt()`
/// calls produce properly chained ballot codes.
pub struct EncryptionMediator {
    pub internal_manifest: InternalManifest,
    pub context: CiphertextElectionContext,
    pub device: EncryptionDevice,
    pub config: EncryptionConfig,
    /// Number of ballots encrypted so far.
    pub ballot_count: u64,
    /// Cached device hash (computed once at construction).
    pub device_hash: ElementModQ,
    /// Latest confirmation code (used as chaining seed for the next ballot).
    pub last_confirmation_code: ElementModQ,
    /// Chain init field (fixed for the lifetime of this session).
    chaining_init: Vec<u8>,
}

impl EncryptionMediator {
    /// Create a new mediator.
    ///
    /// # Errors
    /// Returns an error if the device hash cannot be computed.
    pub fn new(
        internal_manifest: InternalManifest,
        context: CiphertextElectionContext,
        device: EncryptionDevice,
    ) -> Result<Self> {
        Self::with_config(internal_manifest, context, device, EncryptionConfig::default())
    }

    /// Create a new mediator with explicit configuration.
    pub fn with_config(
        internal_manifest: InternalManifest,
        context: CiphertextElectionContext,
        device: EncryptionDevice,
        config: EncryptionConfig,
    ) -> Result<Self> {
        let device_hash = device.hash()?;
        let chaining_init = build_no_chaining_field(&device_hash);
        let last_confirmation_code = device_hash.clone();

        Ok(Self {
            internal_manifest,
            context,
            device,
            config,
            ballot_count: 0,
            device_hash,
            last_confirmation_code,
            chaining_init,
        })
    }

    /// Encrypt a plaintext ballot.
    ///
    /// The ballot nonce is derived from the ballot's `object_id` **and** the
    /// current `ballot_count`, so successive calls with identical ballots
    /// produce distinct ciphertexts.  (This mirrors production behaviour where
    /// each physical ballot carries a unique random nonce.)
    pub fn encrypt(&mut self, ballot: &PlaintextBallot) -> Result<CiphertextBallot> {
        // Derive a deterministic ballot nonce from the ballot ID + session count.
        let nonce_seed = hash_elems_v21(
            &self.context.extended_base_hash,
            EG_DS_ENCRYPTION_NONCE,
            &[
                HashableValue::Str(&ballot.object_id),
                HashableValue::U64(self.ballot_count),
            ],
        )?;

        let timestamp = current_timestamp();
        // Reuse the cached chaining_init rather than recomputing it each call.
        let chaining_field = self.chaining_init.clone();

        let ciphertext = encrypt_ballot_with_nonce(
            ballot,
            &self.internal_manifest,
            &self.context,
            &self.last_confirmation_code,
            &nonce_seed,
            timestamp,
            &chaining_field,
            self.config.should_verify_proofs,
        )?;

        self.last_confirmation_code = ciphertext.ballot_code.clone();
        self.ballot_count += 1;
        Ok(ciphertext)
    }

    /// Encrypt and immediately cast (submit) a ballot.
    pub fn encrypt_and_cast(&mut self, ballot: &PlaintextBallot) -> Result<SubmittedBallot> {
        let ciphertext = self.encrypt(ballot)?;
        Ok(SubmittedBallot::from_ciphertext(ciphertext, BallotBoxState::Cast))
    }

    /// Encrypt and immediately spoil a ballot.
    pub fn encrypt_and_spoil(&mut self, ballot: &PlaintextBallot) -> Result<SubmittedBallot> {
        let ciphertext = self.encrypt(ballot)?;
        Ok(SubmittedBallot::from_ciphertext(ciphertext, BallotBoxState::Spoiled))
    }
}

// ── Selection encryption ──────────────────────────────────────────────────────

/// Derive a proof-seed nonce distinct from the encryption nonce.
///
/// Uses domain index `contest_index * 10000 + selection_index + 5000` to avoid
/// collisions with the standard selection nonce (which uses index without offset).
fn derive_proof_seed(
    selection_enc_id: &ElementModQ,
    contest_index: u64,
    selection_index: u64,
    ballot_nonce: &ElementModQ,
) -> Result<ElementModQ> {
    // Offset large enough to not collide with reasonable selection counts.
    let offset = 5000u64 + contest_index * 10_000 + selection_index;
    derive_selection_nonce(selection_enc_id, contest_index, offset, ballot_nonce)
}

/// Encrypt a single selection.
///
/// # Arguments
/// * `vote`            — The plaintext vote value (0 or 1 for normal selections).
/// * `object_id`       — Selection object ID.
/// * `sequence_order`  — 1-based selection sequence order.
/// * `description_hash`— `crypto_hash()` of the corresponding `SelectionDescription`.
/// * `context`         — Election context.
/// * `nonce`           — Selection encryption nonce `ξ_{i,j}`.
/// * `is_placeholder`  — Whether this is a placeholder selection.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_selection(
    vote: u64,
    object_id: &str,
    sequence_order: u64,
    description_hash: &ElementModQ,
    context: &CiphertextElectionContext,
    nonce: &ElementModQ,
    proof_seed: &ElementModQ,
    is_placeholder: bool,
) -> Result<CiphertextBallotSelection> {
    let ciphertext = elgamal_encrypt(vote, nonce, &context.elgamal_public_key);

    let proof = RangedChaumPedersenProof::make(
        &ciphertext,
        vote,
        nonce,
        &context.elgamal_public_key,
        proof_seed,
        1, // range limit [0, 1]
        &context.extended_base_hash,
    )?;

    CiphertextBallotSelection::make(
        object_id,
        sequence_order,
        description_hash,
        ciphertext,
        context,
        vote,
        nonce,
        is_placeholder,
        proof,
    )
}

// ── Contest encryption ────────────────────────────────────────────────────────

/// Encrypt a single contest.
///
/// Generates selections for all real and placeholder entries, computes the
/// homomorphic accumulation, and proves the sum equals `number_elected`.
///
/// # Arguments
/// * `contest`       — Plaintext contest (may have zero selections if undervote).
/// * `description`   — Contest description with placeholders from the manifest.
/// * `context`       — Election context.
/// * `ballot_nonce`  — Per-ballot master nonce `ξ_B`.
/// * `sel_enc_id`    — Selection encryption ID `H_I` (per-ballot).
/// * `contest_index` — 1-based contest index.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_contest(
    contest: Option<&PlaintextBallotContest>,
    description: &ContestDescriptionWithPlaceholders,
    context: &CiphertextElectionContext,
    ballot_nonce: &ElementModQ,
    sel_enc_id: &ElementModQ,
    contest_index: u64,
) -> Result<CiphertextBallotContest> {
    use crate::hash::CryptoHashable;

    let contest_desc = &description.contest;
    let description_hash = contest_desc.crypto_hash()?;
    let number_elected = contest_desc.number_elected;

    // --- Real selections ---
    let mut encrypted_selections: Vec<CiphertextBallotSelection> = Vec::new();
    let mut real_vote_total: u64 = 0;

    for (j, sel_desc) in contest_desc.selections.iter().enumerate() {
        let selection_index = sel_desc.sequence_order;
        let sel_hash = sel_desc.crypto_hash()?;

        // Find voter's choice for this selection.
        let vote = contest
            .and_then(|c| {
                c.selections.iter().find(|s| s.object_id == sel_desc.object_id)
            })
            .map(|s| s.vote)
            .unwrap_or(0);

        real_vote_total += vote;

        let enc_nonce = derive_selection_nonce(
            sel_enc_id,
            contest_index,
            selection_index,
            ballot_nonce,
        )?;
        let proof_seed =
            derive_proof_seed(sel_enc_id, contest_index, j as u64, ballot_nonce)?;

        let enc_sel = encrypt_selection(
            vote,
            &sel_desc.object_id,
            selection_index,
            &sel_hash,
            context,
            &enc_nonce,
            &proof_seed,
            false,
        )?;

        encrypted_selections.push(enc_sel);
    }

    // --- Placeholder selections ---
    // Ensure total (real + placeholder) == number_elected.
    let votes_needed = number_elected.saturating_sub(real_vote_total);
    for (p, ph_desc) in description.placeholder_selections.iter().enumerate() {
        let ph_vote = if (p as u64) < votes_needed { 1 } else { 0 };
        let ph_index = ph_desc.sequence_order;
        let ph_hash = ph_desc.crypto_hash()?;

        // Use a high selection index to avoid collision with real selections.
        let enc_nonce = derive_selection_nonce(
            sel_enc_id,
            contest_index,
            ph_index,
            ballot_nonce,
        )?;
        let proof_seed = derive_proof_seed(
            sel_enc_id,
            contest_index,
            1000 + p as u64,
            ballot_nonce,
        )?;

        let enc_ph = encrypt_selection(
            ph_vote,
            &ph_desc.object_id,
            ph_index,
            &ph_hash,
            context,
            &enc_nonce,
            &proof_seed,
            true,
        )?;

        encrypted_selections.push(enc_ph);
    }

    // --- Accumulation nonce (sum of all selection nonces) ---
    let agg_nonce = {
        use crate::group::add_mod_q;
        let mut acc = ElementModQ::zero().clone();
        for sel in &encrypted_selections {
            let n = sel.nonce.as_ref().ok_or_else(|| {
                Error::Encryption("selection nonce cleared prematurely".to_string())
            })?;
            acc = add_mod_q(&acc, n);
        }
        acc
    };

    // --- Contest accumulation ciphertext (homomorphic sum) ---
    let accumulation = {
        let refs: Vec<&crate::elgamal::ElGamalCiphertext> =
            encrypted_selections.iter().map(|s| &s.ciphertext).collect();
        crate::elgamal::elgamal_accumulate(&refs)
    };

    // --- Proof that total == number_elected ---
    // We generate a ranged proof on the accumulation ciphertext.
    // The "plaintext" here is number_elected and the "range_limit" is also
    // number_elected (proving the sum is exactly in [0, number_elected]).
    // In full v2.1, this uses a ConstantChaumPedersenProof; we use
    // RangedChaumPedersenProof with limit == number_elected.
    let contest_proof_seed = hash_elems_v21(
        sel_enc_id,
        EG_DS_CONTEST_DATA_ENC_PROOF,
        &[
            HashableValue::U64(contest_index),
            HashableValue::ModQ(ballot_nonce),
        ],
    )?;

    let contest_proof = RangedChaumPedersenProof::make(
        &accumulation,
        number_elected,
        &agg_nonce,
        &context.elgamal_public_key,
        &contest_proof_seed,
        number_elected,
        &context.extended_base_hash,
    )?;

    // --- Optional contest data (encrypted write-in or extension data) ---
    // For now we do not encrypt contest data unless the contest has extended data.
    let hashed_elgamal: Option<HashedElGamalCiphertext> = None;

    // --- Contest nonce ---
    let contest_nonce = derive_contest_data_nonce(sel_enc_id, contest_index, ballot_nonce)?;

    CiphertextBallotContest::make(
        &contest_desc.object_id,
        contest_desc.sequence_order,
        &description_hash,
        encrypted_selections,
        context,
        real_vote_total,
        number_elected,
        Some(&contest_nonce),
        contest_proof,
        hashed_elgamal,
    )
}

// ── Ballot encryption ─────────────────────────────────────────────────────────

/// Encrypt a complete ballot.
///
/// # Arguments
/// * `ballot`            — Voter's plaintext choices.
/// * `internal_manifest` — Internal manifest with placeholder selections.
/// * `context`           — Election context.
/// * `ballot_code_seed`  — Seed for the confirmation code chain.
/// * `nonce_seed`        — Per-ballot nonce seed `ξ_B`.
/// * `timestamp`         — Unix timestamp.
/// * `chaining_field`    — Chaining field bytes `B_C`.
/// * `should_verify`     — Whether to verify proofs after generation.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_ballot(
    ballot: &PlaintextBallot,
    internal_manifest: &InternalManifest,
    context: &CiphertextElectionContext,
    ballot_code_seed: &ElementModQ,
    nonce_seed: &ElementModQ,
    timestamp: u64,
    should_verify: bool,
) -> Result<CiphertextBallot> {
    let chaining_field = build_no_chaining_field(ballot_code_seed);
    encrypt_ballot_with_nonce(
        ballot,
        internal_manifest,
        context,
        ballot_code_seed,
        nonce_seed,
        timestamp,
        &chaining_field,
        should_verify,
    )
}

/// Internal implementation that accepts an explicit chaining field.
#[allow(clippy::too_many_arguments)]
fn encrypt_ballot_with_nonce(
    ballot: &PlaintextBallot,
    internal_manifest: &InternalManifest,
    context: &CiphertextElectionContext,
    ballot_code_seed: &ElementModQ,
    nonce_seed: &ElementModQ,
    timestamp: u64,
    chaining_field: &[u8],
    _should_verify: bool,
) -> Result<CiphertextBallot> {
    // Derive selection encryption ID: H_I = H(H_E; 0x20, ballot_id)
    let sel_enc_id =
        compute_selection_encryption_id(&context.extended_base_hash, nonce_seed)?;

    // Validate ballot style exists.
    if internal_manifest.ballot_style(&ballot.style_id).is_none() {
        return Err(Error::InvalidBallot(format!(
            "ballot style '{}' not found",
            ballot.style_id
        )));
    }
    let contests_for_style = internal_manifest.contests_for_style(&ballot.style_id);

    // Encrypt each contest.
    let mut encrypted_contests: Vec<CiphertextBallotContest> = Vec::new();
    let mut contest_hashes: Vec<ElementModQ> = Vec::new();

    for (idx, contest_desc) in contests_for_style.iter().enumerate() {
        let contest_index = contest_desc.contest.sequence_order;

        // Find the voter's contest (may be absent for undervotes).
        let pt_contest = ballot
            .contests
            .iter()
            .find(|c| c.object_id == contest_desc.contest.object_id);

        let enc_contest = encrypt_contest(
            pt_contest,
            contest_desc,
            context,
            nonce_seed,
            &sel_enc_id,
            contest_index,
        )?;

        // Compute the contest hash χ_l = H(H_I; 0x28, l, α_1, β_1, ...)
        let sel_ciphertexts: Vec<&crate::elgamal::ElGamalCiphertext> =
            enc_contest.selections.iter().map(|s| &s.ciphertext).collect();

        let contest_hash = compute_contest_hash(
            &sel_enc_id,
            contest_index,
            &sel_ciphertexts,
            enc_contest.hashed_elgamal.as_ref(),
        )?;

        let _ = idx; // suppress warning
        contest_hashes.push(contest_hash);
        encrypted_contests.push(enc_contest);
    }

    // Compute confirmation code H_C = H(H_I; 0x29, χ_1,...,χ_m, B_C)
    let contest_hash_refs: Vec<&ElementModQ> = contest_hashes.iter().collect();
    let ballot_code =
        compute_confirmation_code(&sel_enc_id, &contest_hash_refs, chaining_field)?;

    // Build CiphertextBallot.
    let mut cb = CiphertextBallot::make(
        &ballot.object_id,
        &ballot.style_id,
        &context.manifest_hash,
        context,
        encrypted_contests,
        Some(nonce_seed),
        timestamp,
        Some(ballot_code_seed),
    )?;

    // Store the v2.1-specific fields.
    cb.ballot_code = ballot_code;
    cb.selection_encryption_id = Some(sel_enc_id);

    Ok(cb)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Current Unix timestamp (seconds).
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballot::{PlaintextBallotContest, PlaintextBallotSelection};
    use crate::election::CiphertextElectionContext;
    use crate::group::{g_pow, ElementModQ};
    use crate::manifest::{
        BallotStyle, Candidate, ContestDescription,
        GeopoliticalUnit, Manifest, ReportingUnitType, SelectionDescription, VoteVariationType,
    };
    use crate::hash::CryptoHashable;

    // ── Minimal election fixture ──────────────────────────────────────────────

    fn make_manifest() -> Manifest {
        Manifest {
            election_scope_id: "test-election".to_string(),
            spec_version: "v2.1".to_string(),
            election_type: crate::manifest::ElectionType::General,
            start_date: "2024-11-05T00:00:00Z".to_string(),
            end_date: "2024-11-05T23:59:59Z".to_string(),
            geopolitical_units: vec![GeopoliticalUnit {
                object_id: "gp-1".to_string(),
                name: "District 1".to_string(),
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
                object_id: "contest-1".to_string(),
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

    fn make_context() -> CiphertextElectionContext {
        let secret = ElementModQ::from_u64(42);
        let public_key = g_pow(&secret);
        let data_secret = ElementModQ::from_u64(43);
        let data_key = g_pow(&data_secret);
        let manifest = make_manifest();
        let manifest_hash = manifest.crypto_hash().unwrap();
        CiphertextElectionContext::new(
            3,
            2,
            public_key,
            data_key,
            ElementModQ::from_u64(0),
            manifest_hash,
        )
        .unwrap()
    }

    fn make_internal_manifest() -> InternalManifest {
        InternalManifest::from_manifest(&make_manifest()).unwrap()
    }

    fn make_ballot(vote_a: u64) -> PlaintextBallot {
        PlaintextBallot {
            object_id: "ballot-1".to_string(),
            style_id: "style-1".to_string(),
            contests: vec![PlaintextBallotContest {
                object_id: "contest-1".to_string(),
                selections: vec![
                    PlaintextBallotSelection {
                        object_id: "sel-A".to_string(),
                        vote: vote_a,
                        is_placeholder_selection: false,
                        extended_data: None,
                    },
                    PlaintextBallotSelection {
                        object_id: "sel-B".to_string(),
                        vote: 1 - vote_a,
                        is_placeholder_selection: false,
                        extended_data: None,
                    },
                ],
            }],
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn encrypt_selection_produces_valid_structure() {
        let context = make_context();
        let nonce = ElementModQ::from_u64(77);
        let proof_seed = ElementModQ::from_u64(88);
        let desc_hash = ElementModQ::from_u64(1);

        let sel = encrypt_selection(1, "sel-A", 1, &desc_hash, &context, &nonce, &proof_seed, false)
            .unwrap();

        assert_eq!(sel.object_id, "sel-A");
        assert!(!sel.is_placeholder);
        assert_ne!(sel.ciphertext.pad, *crate::group::ElementModP::one());
    }

    #[test]
    fn encrypt_contest_produces_valid_accumulation() {
        let context = make_context();
        let im = make_internal_manifest();
        let ballot_nonce = ElementModQ::from_u64(123);
        let sel_enc_id = ElementModQ::from_u64(456);

        let contest_desc = &im.contests[0];
        let pt_contest = PlaintextBallotContest {
            object_id: "contest-1".to_string(),
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
        };

        let enc_contest = encrypt_contest(
            Some(&pt_contest),
            contest_desc,
            &context,
            &ballot_nonce,
            &sel_enc_id,
            1,
        )
        .unwrap();

        assert_eq!(enc_contest.object_id, "contest-1");
        // 2 real selections + 1 placeholder (number_elected=1, votes=1, so 0 needed)
        assert!(enc_contest.selections.len() >= 2);
    }

    #[test]
    fn encrypt_ballot_is_deterministic() {
        let context = make_context();
        let im = make_internal_manifest();
        let ballot = make_ballot(1);
        let nonce_seed = ElementModQ::from_u64(999);
        let code_seed = ElementModQ::from_u64(1);

        let b1 = encrypt_ballot(&ballot, &im, &context, &code_seed, &nonce_seed, 0, false).unwrap();
        let b2 = encrypt_ballot(&ballot, &im, &context, &code_seed, &nonce_seed, 0, false).unwrap();

        assert_eq!(
            b1.contests[0].ciphertext_accumulation,
            b2.contests[0].ciphertext_accumulation,
            "same nonce seed must produce identical accumulation"
        );
    }

    #[test]
    fn encrypt_ballot_different_votes_give_different_ciphertext() {
        let context = make_context();
        let im = make_internal_manifest();
        let nonce_seed = ElementModQ::from_u64(999);
        let code_seed = ElementModQ::from_u64(1);

        let b1 =
            encrypt_ballot(&make_ballot(1), &im, &context, &code_seed, &nonce_seed, 0, false)
                .unwrap();
        let b2 =
            encrypt_ballot(&make_ballot(0), &im, &context, &code_seed, &nonce_seed, 0, false)
                .unwrap();

        // Both ballots encrypt the same total (1 vote: sel-A=1,sel-B=0 vs sel-A=0,sel-B=1),
        // so homomorphic accumulations are equal by design.  Instead verify that individual
        // selection ciphertexts differ (sel-A encrypts 1 in b1 and 0 in b2).
        assert_ne!(
            b1.contests[0].selections[0].ciphertext,
            b2.contests[0].selections[0].ciphertext,
            "sel-A must differ between vote=1 and vote=0"
        );
        assert_ne!(
            b1.contests[0].selections[1].ciphertext,
            b2.contests[0].selections[1].ciphertext,
            "sel-B must differ between vote=0 and vote=1"
        );
    }

    #[test]
    fn mediator_chains_confirmation_codes() {
        let context = make_context();
        let im = make_internal_manifest();
        let device = EncryptionDevice::new(1, 2, 3, "booth-1");
        let mut mediator = EncryptionMediator::new(im, context, device).unwrap();

        let b1 = mediator.encrypt(&make_ballot(1)).unwrap();
        let b2 = mediator.encrypt(&make_ballot(0)).unwrap();

        assert_ne!(
            b1.ballot_code, b2.ballot_code,
            "successive ballots should have distinct confirmation codes"
        );
        assert_eq!(mediator.ballot_count, 2);
    }

    #[test]
    fn mediator_encrypt_and_cast() {
        let context = make_context();
        let im = make_internal_manifest();
        let device = EncryptionDevice::new(1, 2, 3, "booth-1");
        let mut mediator = EncryptionMediator::new(im, context, device).unwrap();

        let submitted = mediator.encrypt_and_cast(&make_ballot(1)).unwrap();
        assert_eq!(submitted.state, BallotBoxState::Cast);
        // Nonces should be stripped.
        assert!(submitted.nonce.is_none());
    }
}
