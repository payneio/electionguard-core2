//! Ballot code and confirmation code computation.
//!
//! Implements the v2.1 ballot code chain:
//!
//! ```text
//! H_DI = H(H_E; 0x2A, device_info)      — device info hash
//! B_C  = chaining_field                   — see build_* helpers below
//! χ_l  = H(H_I; 0x28, l, α_1,β_1,...,α_n,β_n, [contest_data])  — contest hash
//! H_C  = H(H_I; 0x29, χ_1,...,χ_m, B_C)  — confirmation code
//! H_0  = H(H_E; 0x29, B_{C,0})           — chain init hash
//! H̄    = H(H_E; 0x34, H_{j-1}, B_{C,0}) — chain closing hash
//! ```

use crate::elgamal::{ElGamalCiphertext, HashedElGamalCiphertext};
use crate::error::Result;
use crate::group::ElementModQ;
use crate::group::constants::{
    EG_DS_CHAIN_CLOSING, EG_DS_CONFIRMATION_CODE, EG_DS_CONTEST_HASH, EG_DS_DEVICE_INFO_HASH,
};
use crate::hash::{hash_elems_v21, hash_elems_v21_raw, HashableValue};

// ── Domain separator for chain-closing used below ──────────────────────────
// EG_DS_CHAIN_CLOSING = 0x34 (already in constants)

// ── Device hash ───────────────────────────────────────────────────────────

/// Compute the hash for a specific encryption device.
///
/// ```text
/// H_device = H(0^32; 0x00, device_uuid, session_uuid, launch_code, location)
/// ```
///
/// Uses a zero key (pre-election, no context key yet).
pub fn get_hash_for_device(
    device_uuid: u64,
    session_uuid: u64,
    launch_code: u64,
    location: &str,
) -> Result<ElementModQ> {
    let zero_key = [0u8; 32];
    hash_elems_v21_raw(
        &zero_key,
        0x00,
        &[
            HashableValue::U64(device_uuid),
            HashableValue::U64(session_uuid),
            HashableValue::U64(launch_code),
            HashableValue::Str(location),
        ],
    )
}

/// Compute a ballot confirmation code (rotating hash).
///
/// ```text
/// ballot_code = H(seed; timestamp, ballot_hash)
/// ```
///
/// The seed is typically `H_{j-1}` (the previous ballot's code) or the
/// device hash for the first ballot.
pub fn get_ballot_code(
    seed: &ElementModQ,
    timestamp: u64,
    ballot_hash: &ElementModQ,
) -> Result<ElementModQ> {
    hash_elems_v21(
        seed,
        EG_DS_CONFIRMATION_CODE,
        &[HashableValue::U64(timestamp), HashableValue::ModQ(ballot_hash)],
    )
}

// ── Contest hash ──────────────────────────────────────────────────────────

/// Compute the contest hash `χ_l`.
///
/// ```text
/// χ_l = H(H_I; 0x28, l, α_1,β_1, ..., α_n,β_n, [contest_data])
/// ```
///
/// where `H_I` is the selection encryption ID (a per-ballot ID).
///
/// # Arguments
/// * `selection_enc_id` — the ballot-level selection encryption identifier H_I
/// * `contest_index`    — the 1-based contest index `l`
/// * `selections`       — the selection ciphertexts in sequence order
/// * `contest_data`     — optional hashed ElGamal ciphertext for contest data
pub fn compute_contest_hash(
    selection_enc_id: &ElementModQ,
    contest_index: u64,
    selections: &[&ElGamalCiphertext],
    contest_data: Option<&HashedElGamalCiphertext>,
) -> Result<ElementModQ> {
    let mut args: Vec<HashableValue<'_>> = Vec::with_capacity(1 + 2 * selections.len() + 1);
    args.push(HashableValue::U64(contest_index));

    for ct in selections {
        args.push(HashableValue::ModP(&ct.pad));
        args.push(HashableValue::ModP(&ct.data));
    }

    // If contest data is present, append the MAC (authentication tag).
    if let Some(cd) = contest_data {
        args.push(HashableValue::Bytes(&cd.mac));
    }

    hash_elems_v21(selection_enc_id, EG_DS_CONTEST_HASH, &args)
}

// ── Device info hash ──────────────────────────────────────────────────────

/// Compute the device info hash `H_DI`.
///
/// ```text
/// H_DI = H(H_E; 0x2A, S_device)
/// ```
///
/// where `S_device` is a device information string (e.g. hostname, serial number).
pub fn compute_device_info_hash(
    extended_hash: &ElementModQ,
    device_info: &str,
) -> Result<ElementModQ> {
    hash_elems_v21(
        extended_hash,
        EG_DS_DEVICE_INFO_HASH,
        &[HashableValue::Str(device_info)],
    )
}

// ── Confirmation code ─────────────────────────────────────────────────────

/// Compute the ballot confirmation code `H_C`.
///
/// ```text
/// H_C = H(H_I; 0x29, χ_1, ..., χ_m, B_C)
/// ```
///
/// # Arguments
/// * `selection_enc_id` — H_I (selection encryption identifier)
/// * `contest_hashes`   — the per-contest hashes `χ_1, ..., χ_m`
/// * `chaining_field`   — the chaining field bytes B_C
pub fn compute_confirmation_code(
    selection_enc_id: &ElementModQ,
    contest_hashes: &[&ElementModQ],
    chaining_field: &[u8],
) -> Result<ElementModQ> {
    let mut args: Vec<HashableValue<'_>> = Vec::with_capacity(contest_hashes.len() + 1);
    for &ch in contest_hashes {
        args.push(HashableValue::ModQ(ch));
    }
    args.push(HashableValue::Bytes(chaining_field));

    hash_elems_v21(selection_enc_id, EG_DS_CONFIRMATION_CODE, &args)
}

// ── Chaining field helpers ────────────────────────────────────────────────

/// Chaining mode tag byte: no chaining.
const CHAIN_MODE_NONE: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
/// Chaining mode tag byte: simple chain.
const CHAIN_MODE_SIMPLE: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// **No-chain**: `B_C = 0x00000000 || H_DI`
///
/// Use this when confirmation codes should not be chained across ballots.
pub fn build_no_chaining_field(device_info_hash: &ElementModQ) -> Vec<u8> {
    let mut field = Vec::with_capacity(4 + 32);
    field.extend_from_slice(&CHAIN_MODE_NONE);
    field.extend_from_slice(&device_info_hash.to_bytes_be());
    field
}

/// **Simple-chain init**: `B_{C,0} = 0x00000001 || H_DI`
///
/// Use this for the first ballot in a chain.
pub fn build_simple_chain_init_field(device_info_hash: &ElementModQ) -> Vec<u8> {
    let mut field = Vec::with_capacity(4 + 32);
    field.extend_from_slice(&CHAIN_MODE_SIMPLE);
    field.extend_from_slice(&device_info_hash.to_bytes_be());
    field
}

/// **Simple-chain continuation**: `B_{C,j} = 0x00000001 || H_{j-1}`
///
/// Use this for ballot `j > 0` in a chain; `previous_hash` is the confirmation
/// code of ballot `j-1`.
pub fn build_simple_chain_field(previous_hash: &ElementModQ) -> Vec<u8> {
    let mut field = Vec::with_capacity(4 + 32);
    field.extend_from_slice(&CHAIN_MODE_SIMPLE);
    field.extend_from_slice(&previous_hash.to_bytes_be());
    field
}

// ── Chain init / closing ──────────────────────────────────────────────────

/// Compute the chain initialisation hash `H_0`.
///
/// ```text
/// H_0 = H(H_E; 0x29, B_{C,0})
/// ```
pub fn compute_chain_init_hash(
    extended_hash: &ElementModQ,
    init_field: &[u8],
) -> Result<ElementModQ> {
    hash_elems_v21(
        extended_hash,
        EG_DS_CONFIRMATION_CODE,
        &[HashableValue::Bytes(init_field)],
    )
}

/// Compute the chain closing hash `H̄`.
///
/// ```text
/// H̄ = H(H_E; 0x34, H_{j-1}, B_{C,0})
/// ```
///
/// # Arguments
/// * `extended_hash` — H_E
/// * `last_hash`     — the confirmation code of the last ballot in the chain
/// * `init_field`    — the initial chaining field `B_{C,0}`
pub fn close_chain(
    extended_hash: &ElementModQ,
    last_hash: &ElementModQ,
    init_field: &[u8],
) -> Result<ElementModQ> {
    hash_elems_v21(
        extended_hash,
        EG_DS_CHAIN_CLOSING,
        &[HashableValue::ModQ(last_hash), HashableValue::Bytes(init_field)],
    )
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{ElementModP, ElementModQ};

    fn dummy_q(n: u64) -> ElementModQ {
        ElementModQ::from_u64(n)
    }
    fn dummy_p() -> ElementModP {
        ElementModP::g().clone()
    }
    fn dummy_ct() -> ElGamalCiphertext {
        ElGamalCiphertext { pad: dummy_p(), data: dummy_p() }
    }

    #[test]
    fn device_hash_deterministic() {
        let h1 = get_hash_for_device(1, 2, 3, "booth-1").unwrap();
        let h2 = get_hash_for_device(1, 2, 3, "booth-1").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn device_hash_varies_by_input() {
        let h1 = get_hash_for_device(1, 2, 3, "booth-1").unwrap();
        let h2 = get_hash_for_device(1, 2, 3, "booth-2").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn ballot_code_deterministic() {
        let seed = dummy_q(42);
        let ballot_hash = dummy_q(99);
        let c1 = get_ballot_code(&seed, 1000, &ballot_hash).unwrap();
        let c2 = get_ballot_code(&seed, 1000, &ballot_hash).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn ballot_code_varies_by_timestamp() {
        let seed = dummy_q(1);
        let bh = dummy_q(2);
        let c1 = get_ballot_code(&seed, 1000, &bh).unwrap();
        let c2 = get_ballot_code(&seed, 1001, &bh).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn contest_hash_deterministic() {
        let enc_id = dummy_q(7);
        let ct = dummy_ct();
        let h1 = compute_contest_hash(&enc_id, 1, &[&ct], None).unwrap();
        let h2 = compute_contest_hash(&enc_id, 1, &[&ct], None).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn contest_hash_varies_by_index() {
        let enc_id = dummy_q(7);
        let ct = dummy_ct();
        let h1 = compute_contest_hash(&enc_id, 1, &[&ct], None).unwrap();
        let h2 = compute_contest_hash(&enc_id, 2, &[&ct], None).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn device_info_hash_deterministic() {
        let he = dummy_q(5);
        let h1 = compute_device_info_hash(&he, "my-device").unwrap();
        let h2 = compute_device_info_hash(&he, "my-device").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn device_info_hash_varies_by_name() {
        let he = dummy_q(5);
        let h1 = compute_device_info_hash(&he, "device-A").unwrap();
        let h2 = compute_device_info_hash(&he, "device-B").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn confirmation_code_deterministic() {
        let enc_id = dummy_q(3);
        let ch1 = dummy_q(10);
        let ch2 = dummy_q(11);
        let chaining = build_no_chaining_field(&dummy_q(99));
        let c1 = compute_confirmation_code(&enc_id, &[&ch1, &ch2], &chaining).unwrap();
        let c2 = compute_confirmation_code(&enc_id, &[&ch1, &ch2], &chaining).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn no_chaining_field_structure() {
        let dih = dummy_q(42);
        let field = build_no_chaining_field(&dih);
        assert_eq!(&field[0..4], &CHAIN_MODE_NONE);
        assert_eq!(&field[4..], &dih.to_bytes_be());
    }

    #[test]
    fn simple_chain_init_field_structure() {
        let dih = dummy_q(42);
        let field = build_simple_chain_init_field(&dih);
        assert_eq!(&field[0..4], &CHAIN_MODE_SIMPLE);
        assert_eq!(&field[4..], &dih.to_bytes_be());
    }

    #[test]
    fn simple_chain_field_structure() {
        let prev = dummy_q(11);
        let field = build_simple_chain_field(&prev);
        assert_eq!(&field[0..4], &CHAIN_MODE_SIMPLE);
        assert_eq!(&field[4..], &prev.to_bytes_be());
    }

    #[test]
    fn chain_init_hash_deterministic() {
        let he = dummy_q(5);
        let dih = dummy_q(42);
        let init = build_simple_chain_init_field(&dih);
        let h1 = compute_chain_init_hash(&he, &init).unwrap();
        let h2 = compute_chain_init_hash(&he, &init).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn close_chain_deterministic() {
        let he = dummy_q(5);
        let last = dummy_q(99);
        let dih = dummy_q(42);
        let init = build_simple_chain_init_field(&dih);
        let h1 = close_chain(&he, &last, &init).unwrap();
        let h2 = close_chain(&he, &last, &init).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn chain_hash_chain_is_distinct() {
        let he = dummy_q(7);
        let dih = dummy_q(1);
        let init = build_simple_chain_init_field(&dih);

        let h0 = compute_chain_init_hash(&he, &init).unwrap();

        // Simulate two chained ballots.
        let ballot_hash1 = dummy_q(100);
        let cf1 = build_simple_chain_field(&h0);
        let enc_id = dummy_q(5);
        let chi1 = compute_contest_hash(&enc_id, 1, &[], None).unwrap();
        let hc1 = compute_confirmation_code(&enc_id, &[&chi1], &cf1).unwrap();

        let ballot_hash2 = dummy_q(101);
        let cf2 = build_simple_chain_field(&hc1);
        let chi2 = compute_contest_hash(&enc_id, 1, &[], None).unwrap();
        let hc2 = compute_confirmation_code(&enc_id, &[&chi2], &cf2).unwrap();

        // All distinct (with high probability).
        assert_ne!(h0, hc1);
        assert_ne!(hc1, hc2);
        let _ = ballot_hash1;
        let _ = ballot_hash2;

        let hbar = close_chain(&he, &hc2, &init).unwrap();
        assert_ne!(hbar, hc2);
    }
}
