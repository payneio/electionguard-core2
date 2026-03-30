
// RED: This file imports from './models' which does not exist yet.
// All expectations here will fail until models.ts is created with the v2.1 interfaces.

import {
  ElectionContextJson,
  CiphertextBallotJson,
  GuardianJson,
} from './models';

describe('Angular Demo Data Models v2.1', () => {
  // ── ElectionContextJson ────────────────────────────────────────────────────

  it('ElectionContextJson should accept ballotDataPublicKey field', () => {
    const ctx: ElectionContextJson = {
      number_of_guardians: 5,
      quorum: 3,
      elgamal_public_key: 'AABBCC',
      commitment_hash: 'DDEEFF',
      manifest_hash: '112233',
      crypto_base_hash: '445566',
      crypto_extended_base_hash: '778899',
      ballot_data_public_key: 'FFEEDD', // v2.1: K_hat
    };
    expect(ctx.ballot_data_public_key).toBe('FFEEDD');
  });

  it('ElectionContextJson should allow ballot_data_public_key to be optional', () => {
    const ctx: ElectionContextJson = {
      number_of_guardians: 3,
      quorum: 2,
      elgamal_public_key: 'AABBCC',
      commitment_hash: 'DDEEFF',
      manifest_hash: '112233',
      crypto_base_hash: '445566',
      crypto_extended_base_hash: '778899',
      // ballot_data_public_key omitted — must be optional
    };
    expect(ctx.ballot_data_public_key).toBeUndefined();
  });

  // ── CiphertextBallotJson ───────────────────────────────────────────────────

  it('CiphertextBallotJson should accept v2.1 ballotId field (id_B)', () => {
    const ballot: CiphertextBallotJson = {
      object_id: 'b-001',
      style_id: 'style-1',
      manifest_hash: 'ABC',
      code_seed: 'DEF',
      code: 'GHI',
      contests: [],
      timestamp: 1_700_000_000,
      crypto_hash: 'JKL',
      state: 1,
      ballot_id: 'id-B-hex-value', // v2.1: id_B
    };
    expect(ballot.ballot_id).toBe('id-B-hex-value');
  });

  it('CiphertextBallotJson should accept optional nonce_ciphertext', () => {
    const ballot: CiphertextBallotJson = {
      object_id: 'b-002',
      style_id: 'style-1',
      manifest_hash: 'ABC',
      code_seed: 'DEF',
      code: 'GHI',
      contests: [],
      timestamp: 1_700_000_001,
      crypto_hash: 'JKL',
      state: 1,
      nonce_ciphertext: { pad: 'PAD_HEX', data: 'DATA_HEX' }, // v2.1
    };
    expect(ballot.nonce_ciphertext).toBeDefined();
    expect(ballot.nonce_ciphertext?.['pad']).toBe('PAD_HEX');
  });

  it('CiphertextBallotJson should accept optional chainingMode and chainingField', () => {
    const ballot: CiphertextBallotJson = {
      object_id: 'b-003',
      style_id: 'style-1',
      manifest_hash: 'ABC',
      code_seed: 'DEF',
      code: 'GHI',
      contests: [],
      timestamp: 1_700_000_002,
      crypto_hash: 'JKL',
      state: 1,
      chaining_mode: 'hash', // v2.1
      chaining_field: 'CHAIN_HEX', // v2.1
    };
    expect(ballot.chaining_mode).toBe('hash');
    expect(ballot.chaining_field).toBe('CHAIN_HEX');
  });

  // ── GuardianJson ───────────────────────────────────────────────────────────

  it('GuardianJson should have triple public key fields (v2.1)', () => {
    const g: GuardianJson = {
      guardian_id: 'g-1',
      sequence_order: 1,
      vote_public_key: 'VOTE_KEY_HEX',      // v2.1: K_i
      data_public_key: 'DATA_KEY_HEX',      // v2.1: K̂_i
      communication_public_key: 'COMM_KEY_HEX', // v2.1: κ_i
    };
    expect(g.vote_public_key).toBe('VOTE_KEY_HEX');
    expect(g.data_public_key).toBe('DATA_KEY_HEX');
    expect(g.communication_public_key).toBe('COMM_KEY_HEX');
  });

  it('GuardianJson should allow triple key fields to be optional', () => {
    const g: GuardianJson = {
      guardian_id: 'g-2',
      sequence_order: 2,
      // key fields omitted — must be optional
    };
    expect(g.vote_public_key).toBeUndefined();
  });
});
