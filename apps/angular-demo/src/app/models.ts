
/**
 * TypeScript data models for the ElectionGuard v2.1 Angular demo.
 *
 * These interfaces represent the JSON shapes exchanged with the server
 * (or loaded from test-data.json).  All v2.1 additions are marked optional
 * so that v1 payloads remain assignable to the same types.
 */

// ── Shared primitives ────────────────────────────────────────────────────────

/**
 * An ElGamal ciphertext element as it appears in JSON.
 * Both components are big-endian hex-encoded 256-byte integers (mod p).
 */
export interface ElGamalCiphertextJson {
  pad: string;  // α  (hex)
  data: string; // β  (hex)
}

// ── Election context ─────────────────────────────────────────────────────────

/**
 * JSON shape of a `CiphertextElectionContext`.
 */
export interface ElectionContextJson {
  /** Number of guardians n. */
  number_of_guardians: number;
  /** Decryption quorum k. */
  quorum: number;
  /** Joint vote public key K  (hex-encoded ElementModP). */
  elgamal_public_key: string;
  /** H(K_1, …, K_n)  (hex-encoded ElementModQ). */
  commitment_hash: string;
  /** Manifest hash (hex-encoded ElementModQ). */
  manifest_hash: string;
  /** Base hash Q  (hex-encoded ElementModQ). */
  crypto_base_hash: string;
  /** Extended base hash Q̄  (hex-encoded ElementModQ). */
  crypto_extended_base_hash: string;

  // ── v2.1 additions ────────────────────────────────────────────────────────
  /**
   * Ballot-data public key K̂ = g^{s̃} mod p  (hex-encoded ElementModP).
   * v2.1 field — spec ref: §3.2, "K_hat".
   */
  ballot_data_public_key?: string;
}

// ── Ballot ───────────────────────────────────────────────────────────────────

/**
 * JSON shape of an encrypted `CiphertextBallot`.
 */
export interface CiphertextBallotJson {
  /** Corresponds to `object_id` in legacy JSON; unique ballot identifier. */
  object_id: string;
  /** Ballot style identifier from the manifest. */
  style_id: string;
  /** Hash of the election manifest (hex-encoded ElementModQ). */
  manifest_hash: string;
  /** Chaining seed — device hash or previous ballot code  (hex-encoded ElementModQ). */
  code_seed: string;
  /** Ballot confirmation code  (hex-encoded ElementModQ). */
  code: string;
  /** Encrypted contests on this ballot. */
  contests: unknown[];
  /** Unix timestamp (seconds) when the ballot was encrypted. */
  timestamp: number;
  /** Aggregate crypto hash of all contest hashes  (hex-encoded ElementModQ). */
  crypto_hash: string;
  /** Ballot disposition: 1 = cast, 2 = challenged / spoiled. */
  state: number;

  // ── v2.1 additions ────────────────────────────────────────────────────────
  /**
   * Unique ballot identifier id_B  (hex-encoded ElementModQ).
   * v2.1 field — spec ref: §5.1.
   */
  ballot_id?: string;
  /**
   * Encryption of the ballot nonce under K̂  (ElGamal ciphertext).
   * v2.1 field — spec ref: §5.2, "nonce ciphertext".
   */
  nonce_ciphertext?: ElGamalCiphertextJson;
  /**
   * Chaining mode identifier (e.g. "hash", "none").
   * v2.1 field — spec ref: §5.3.
   */
  chaining_mode?: string;
  /**
   * Chaining field value  (hex-encoded ElementModQ).
   * v2.1 field — spec ref: §5.3.
   */
  chaining_field?: string;
}

// ── Guardian ─────────────────────────────────────────────────────────────────

/**
 * JSON shape of a guardian record.
 * The v2.1 spec introduces a *triple key pair* for each guardian.
 */
export interface GuardianJson {
  /** Application-level guardian identifier string. */
  guardian_id: string;
  /** 1-based index i in the guardian set. */
  sequence_order: number;

  // ── v2.1 additions ────────────────────────────────────────────────────────
  /**
   * Vote commitment public key K_i = g^{s_i} mod p  (hex-encoded ElementModP).
   * v2.1 field — spec ref: §3.2.
   */
  vote_public_key?: string;
  /**
   * Data commitment public key K̂_i = g^{ŝ_i} mod p  (hex-encoded ElementModP).
   * v2.1 field — spec ref: §3.2.
   */
  data_public_key?: string;
  /**
   * Communication public key κ_i = g^{ζ_i} mod p  (hex-encoded ElementModP).
   * v2.1 field — spec ref: §3.2.
   */
  communication_public_key?: string;
}
