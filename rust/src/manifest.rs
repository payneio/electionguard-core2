//! Election manifest types and internal manifest with placeholder selections.
//!
//! The `Manifest` is the immutable, human-readable description of an election.
//! `InternalManifest` extends it with ElectionGuard placeholder selections and
//! a precomputed `manifest_hash` used in the hash chain.

use crate::error::{Error, Result};
use crate::group::ElementModQ;
use crate::hash::{hash_elems_v21_raw, CryptoHashable, HashableValue};
use serde::{Deserialize, Serialize};

// ── Domain Enumerations ────────────────────────────────────────────────────

/// Top-level election type.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ElectionType {
    #[default]
    Unknown,
    General,
    PartisanPrimaryClosed,
    PartisanPrimaryOpen,
    Primary,
    Runoff,
    Special,
    Other,
}

/// Type of a reporting unit (district, precinct, etc.).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReportingUnitType {
    #[default]
    Unknown,
    BallotBatch,
    BallotStyleArea,
    Borough,
    City,
    CityCouncil,
    CombinedPrecinct,
    Congressional,
    Country,
    County,
    CountyCouncil,
    DropBox,
    Judicial,
    Municipality,
    PollingPlace,
    Precinct,
    School,
    Special,
    SplitPrecinct,
    State,
    StateHouse,
    StateSenate,
    Township,
    Utility,
    Village,
    VoteCenter,
    Ward,
    Water,
    Other,
}

/// Voting variation / ballot type.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VoteVariationType {
    #[default]
    Unknown,
    OneOfM,
    Approval,
    Borda,
    Cumulative,
    Majority,
    NOfM,
    Plurality,
    Proportional,
    Range,
    Rcv,
    SuperMajority,
    Other,
}

// ── Common Data Types ──────────────────────────────────────────────────────

/// A string with an annotation/label.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnotatedString {
    pub annotation: String,
    pub value: String,
}

/// A single localized language string.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Language {
    pub value: String,
    pub language: String,
}

/// A collection of localized strings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InternationalizedText {
    pub text: Vec<Language>,
}

/// Contact information for a geopolitical unit or party.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactInformation {
    pub name: Option<String>,
    #[serde(default)]
    pub address_line: Vec<String>,
    #[serde(default)]
    pub email: Vec<AnnotatedString>,
    #[serde(default)]
    pub phone: Vec<AnnotatedString>,
}

/// A geopolitical unit (district, precinct, county, etc.).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeopoliticalUnit {
    pub object_id: String,
    pub name: String,
    pub reporting_unit_type: ReportingUnitType,
    pub contact_information: Option<ContactInformation>,
}

/// A ballot style — lists the geopolitical units and optional party affiliations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BallotStyle {
    pub object_id: String,
    #[serde(default)]
    pub geopolitical_unit_ids: Vec<String>,
    #[serde(default)]
    pub party_ids: Vec<String>,
    pub image_uri: Option<String>,
}

/// A political party.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Party {
    pub object_id: String,
    pub name: Option<InternationalizedText>,
    pub abbreviation: Option<String>,
    pub color: Option<String>,
    pub logo_uri: Option<String>,
}

/// A candidate appearing on a ballot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub object_id: String,
    pub name: Option<InternationalizedText>,
    pub party_id: Option<String>,
    pub image_uri: Option<String>,
    #[serde(default)]
    pub is_write_in: bool,
}

/// A single selection within a contest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectionDescription {
    pub object_id: String,
    pub candidate_id: String,
    pub sequence_order: u64,
}

/// A contest (race) in the election.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContestDescription {
    pub object_id: String,
    pub electoral_district_id: String,
    pub sequence_order: u64,
    pub vote_variation: VoteVariationType,
    pub number_elected: u64,
    pub votes_allowed: Option<u64>,
    pub name: String,
    pub ballot_title: Option<InternationalizedText>,
    pub ballot_subtitle: Option<InternationalizedText>,
    #[serde(default)]
    pub selections: Vec<SelectionDescription>,
    #[serde(default)]
    pub primary_party_ids: Vec<String>,
}

impl ContestDescription {
    /// Returns `true` if the contest is structurally valid.
    pub fn is_valid(&self) -> bool {
        if self.object_id.is_empty() || self.electoral_district_id.is_empty() {
            return false;
        }
        if self.number_elected == 0 {
            return false;
        }
        if self.selections.is_empty() {
            return false;
        }
        // number_elected must not exceed the number of selections
        if self.number_elected as usize > self.selections.len() {
            return false;
        }
        // All selection object_ids must be unique
        let mut seen = std::collections::HashSet::new();
        for sel in &self.selections {
            if !seen.insert(&sel.object_id) {
                return false;
            }
        }
        true
    }

    /// Returns `votes_allowed` if set, otherwise defaults to `number_elected`.
    pub fn effective_votes_allowed(&self) -> u64 {
        self.votes_allowed.unwrap_or(self.number_elected)
    }
}

/// A `ContestDescription` with placeholder selections for ElectionGuard encryption.
///
/// Placeholder selections are synthetic selections used to ensure each encrypted
/// contest has exactly `number_elected` "voted" selections total.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContestDescriptionWithPlaceholders {
    /// The underlying contest (flattened into JSON).
    #[serde(flatten)]
    pub contest: ContestDescription,
    /// Auto-generated placeholder selections.
    #[serde(default)]
    pub placeholder_selections: Vec<SelectionDescription>,
}

impl ContestDescriptionWithPlaceholders {
    /// Returns `true` if the selection with `selection_id` is a placeholder.
    pub fn is_placeholder(&self, selection_id: &str) -> bool {
        self.placeholder_selections.iter().any(|s| s.object_id == selection_id)
    }

    /// Find a selection (real or placeholder) by its `object_id`.
    pub fn selection_for(&self, selection_id: &str) -> Option<&SelectionDescription> {
        self.contest
            .selections
            .iter()
            .find(|s| s.object_id == selection_id)
            .or_else(|| {
                self.placeholder_selections
                    .iter()
                    .find(|s| s.object_id == selection_id)
            })
    }

    /// Total number of selections including placeholders.
    pub fn total_selections(&self) -> usize {
        self.contest.selections.len() + self.placeholder_selections.len()
    }
}

// ── Manifest ───────────────────────────────────────────────────────────────

/// The election manifest — the immutable human-readable description of an election.
///
/// This is the top-level input to ElectionGuard.  Its `crypto_hash()` feeds
/// directly into the parameter-hash chain (`H_P → H_B → H_E`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub election_scope_id: String,
    pub spec_version: String,
    pub election_type: ElectionType,
    /// ISO 8601 date-time string.
    pub start_date: String,
    /// ISO 8601 date-time string.
    pub end_date: String,
    #[serde(default)]
    pub geopolitical_units: Vec<GeopoliticalUnit>,
    #[serde(default)]
    pub parties: Vec<Party>,
    #[serde(default)]
    pub candidates: Vec<Candidate>,
    #[serde(default)]
    pub contests: Vec<ContestDescription>,
    #[serde(default)]
    pub ballot_styles: Vec<BallotStyle>,
    pub name: Option<InternationalizedText>,
    pub contact_information: Option<ContactInformation>,
}

impl Manifest {
    /// Deserialize from a JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| Error::Serialization(format!("Manifest::from_json: {}", e)))
    }

    /// Serialize to a JSON string.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| Error::Serialization(format!("Manifest::to_json: {}", e)))
    }

    /// Returns `true` if this manifest is structurally valid.
    pub fn is_valid(&self) -> bool {
        if self.election_scope_id.is_empty() {
            return false;
        }
        if self.contests.is_empty() {
            return false;
        }
        if !self.contests.iter().all(|c| c.is_valid()) {
            return false;
        }
        if self.ballot_styles.is_empty() {
            return false;
        }
        true
    }
}

impl CryptoHashable for Manifest {
    /// Compute the manifest hash.
    ///
    /// The manifest is serialized to canonical JSON and hashed with a zero
    /// HMAC key (the same approach as the parameter hash).  The result is
    /// used as `manifest_hash` in `CiphertextElectionContext`.
    fn crypto_hash(&self) -> Result<ElementModQ> {
        let json = self.to_json()?;
        let zero_key = [0u8; 32];
        // Domain separator 0x01 distinguishes the manifest hash from the
        // parameter hash (which uses 0x00).
        hash_elems_v21_raw(&zero_key, 0x01, &[HashableValue::Str(&json)])
    }
}

// ── CryptoHashable for sub-types ───────────────────────────────────────────
//
// These hashes are used as `description_hash` fields inside encrypted ballots.

impl CryptoHashable for SelectionDescription {
    fn crypto_hash(&self) -> Result<ElementModQ> {
        let zero_key = [0u8; 32];
        hash_elems_v21_raw(
            &zero_key,
            0x00,
            &[
                HashableValue::Str(&self.object_id),
                HashableValue::Str(&self.candidate_id),
                HashableValue::U64(self.sequence_order),
            ],
        )
    }
}

impl CryptoHashable for ContestDescription {
    fn crypto_hash(&self) -> Result<ElementModQ> {
        // Hash all selection description hashes so the contest hash binds
        // the exact set of selections.
        let sel_hashes: Result<Vec<ElementModQ>> =
            self.selections.iter().map(|s| s.crypto_hash()).collect();
        let sel_hashes = sel_hashes?;

        let zero_key = [0u8; 32];

        let mut args: Vec<HashableValue<'_>> = vec![
            HashableValue::Str(&self.object_id),
            HashableValue::Str(&self.electoral_district_id),
            HashableValue::U64(self.sequence_order),
            HashableValue::U64(self.number_elected),
        ];
        if let Some(va) = self.votes_allowed {
            args.push(HashableValue::U64(va));
        }
        for sh in &sel_hashes {
            args.push(HashableValue::ModQ(sh));
        }

        hash_elems_v21_raw(&zero_key, 0x00, &args)
    }
}

impl CryptoHashable for GeopoliticalUnit {
    fn crypto_hash(&self) -> Result<ElementModQ> {
        let zero_key = [0u8; 32];
        hash_elems_v21_raw(
            &zero_key,
            0x00,
            &[
                HashableValue::Str(&self.object_id),
                HashableValue::Str(&self.name),
            ],
        )
    }
}

impl CryptoHashable for BallotStyle {
    fn crypto_hash(&self) -> Result<ElementModQ> {
        let zero_key = [0u8; 32];
        hash_elems_v21_raw(&zero_key, 0x00, &[HashableValue::Str(&self.object_id)])
    }
}

impl CryptoHashable for Party {
    fn crypto_hash(&self) -> Result<ElementModQ> {
        let zero_key = [0u8; 32];
        hash_elems_v21_raw(&zero_key, 0x00, &[HashableValue::Str(&self.object_id)])
    }
}

impl CryptoHashable for Candidate {
    fn crypto_hash(&self) -> Result<ElementModQ> {
        let zero_key = [0u8; 32];
        hash_elems_v21_raw(&zero_key, 0x00, &[HashableValue::Str(&self.object_id)])
    }
}

// ── InternalManifest ───────────────────────────────────────────────────────

/// An internal manifest with pre-computed manifest hash and placeholder selections.
///
/// Created from a [`Manifest`] via [`InternalManifest::from_manifest`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InternalManifest {
    /// Pre-computed hash of the source `Manifest`.
    pub manifest_hash: ElementModQ,
    pub geopolitical_units: Vec<GeopoliticalUnit>,
    pub candidates: Vec<Candidate>,
    /// Contests augmented with placeholder selections.
    pub contests: Vec<ContestDescriptionWithPlaceholders>,
    pub ballot_styles: Vec<BallotStyle>,
}

impl InternalManifest {
    /// Build an `InternalManifest` from a `Manifest`.
    ///
    /// For each contest, generates `number_elected` placeholder selections
    /// with `sequence_order` values that do not collide with real selections.
    pub fn from_manifest(manifest: &Manifest) -> Result<Self> {
        let manifest_hash = manifest.crypto_hash()?;

        let contests = manifest
            .contests
            .iter()
            .map(|contest| {
                let max_seq = contest
                    .selections
                    .iter()
                    .map(|s| s.sequence_order)
                    .max()
                    .unwrap_or(0);

                let placeholder_selections = (0..contest.number_elected)
                    .map(|i| generate_placeholder_selection(contest, max_seq + 1 + i))
                    .collect();

                ContestDescriptionWithPlaceholders {
                    contest: contest.clone(),
                    placeholder_selections,
                }
            })
            .collect();

        Ok(InternalManifest {
            manifest_hash,
            geopolitical_units: manifest.geopolitical_units.clone(),
            candidates: manifest.candidates.clone(),
            contests,
            ballot_styles: manifest.ballot_styles.clone(),
        })
    }

    /// Return all contests that apply to the given ballot style.
    ///
    /// A contest applies to a style if its `electoral_district_id` is in the
    /// style's `geopolitical_unit_ids` list.
    pub fn contests_for_style(
        &self,
        style_id: &str,
    ) -> Vec<&ContestDescriptionWithPlaceholders> {
        let style = match self.ballot_styles.iter().find(|s| s.object_id == style_id) {
            Some(s) => s,
            None => return Vec::new(),
        };

        self.contests
            .iter()
            .filter(|c| {
                style
                    .geopolitical_unit_ids
                    .iter()
                    .any(|g| g == &c.contest.electoral_district_id)
            })
            .collect()
    }

    /// Look up a ballot style by its `object_id`.
    pub fn ballot_style(&self, style_id: &str) -> Option<&BallotStyle> {
        self.ballot_styles.iter().find(|s| s.object_id == style_id)
    }

    /// Deserialize from a JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| Error::Serialization(format!("InternalManifest::from_json: {}", e)))
    }

    /// Serialize to a JSON string.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| Error::Serialization(format!("InternalManifest::to_json: {}", e)))
    }
}

// ── Placeholder generation ─────────────────────────────────────────────────

/// Generate a placeholder `SelectionDescription` for `contest` at position `sequence_id`.
///
/// Placeholder object_ids are guaranteed not to conflict with real selections
/// because they use the format `"{contest_id}-placeholder-{seq}"`.
pub fn generate_placeholder_selection(
    contest: &ContestDescription,
    sequence_id: u64,
) -> SelectionDescription {
    let object_id = format!("{}-placeholder-{}", contest.object_id, sequence_id);
    SelectionDescription {
        candidate_id: object_id.clone(),
        object_id,
        sequence_order: sequence_id,
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> Manifest {
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

    #[test]
    fn manifest_is_valid() {
        let m = sample_manifest();
        assert!(m.is_valid());
    }

    #[test]
    fn manifest_invalid_empty_contests() {
        let mut m = sample_manifest();
        m.contests.clear();
        assert!(!m.is_valid());
    }

    #[test]
    fn manifest_json_round_trip() {
        let m = sample_manifest();
        let json = m.to_json().unwrap();
        let m2 = Manifest::from_json(&json).unwrap();
        assert_eq!(m.election_scope_id, m2.election_scope_id);
        assert_eq!(m.contests.len(), m2.contests.len());
    }

    #[test]
    fn manifest_crypto_hash_deterministic() {
        let m = sample_manifest();
        let h1 = m.crypto_hash().unwrap();
        let h2 = m.crypto_hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn internal_manifest_from_manifest_generates_placeholders() {
        let m = sample_manifest();
        let im = InternalManifest::from_manifest(&m).unwrap();
        // One contest with number_elected=1 → 1 placeholder
        assert_eq!(im.contests.len(), 1);
        assert_eq!(im.contests[0].placeholder_selections.len(), 1);
        let ph = &im.contests[0].placeholder_selections[0];
        assert!(ph.object_id.contains("placeholder"));
    }

    #[test]
    fn internal_manifest_contests_for_style() {
        let m = sample_manifest();
        let im = InternalManifest::from_manifest(&m).unwrap();
        let contests = im.contests_for_style("style-1");
        assert_eq!(contests.len(), 1);
        let empty = im.contests_for_style("no-such-style");
        assert!(empty.is_empty());
    }

    #[test]
    fn contest_description_crypto_hash_deterministic() {
        let m = sample_manifest();
        let h1 = m.contests[0].crypto_hash().unwrap();
        let h2 = m.contests[0].crypto_hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn selection_description_crypto_hash_deterministic() {
        let m = sample_manifest();
        let sel = &m.contests[0].selections[0];
        let h1 = sel.crypto_hash().unwrap();
        let h2 = sel.crypto_hash().unwrap();
        assert_eq!(h1, h2);
    }
}
