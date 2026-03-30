import { GuardianKeySetHandle } from "./wasm/electionguard";
import { getInstance } from "./wasm";
import { ElementModP } from "./group";

export class GuardianKeySet {
  _handle: GuardianKeySetHandle;

  constructor(handle: GuardianKeySetHandle) {
    this._handle = handle;
  }

  /**
   * Vote public key K_i = g^{s_i} mod p (= voteCommitments[0]).
   */
  get votePublicKey(): ElementModP {
    return new ElementModP(this._handle.getVotePublicKey());
  }

  /**
   * Data public key K̂_i = g^{ŝ_i} mod p (= dataCommitments[0]).
   */
  get dataPublicKey(): ElementModP {
    return new ElementModP(this._handle.getDataPublicKey());
  }

  /**
   * Communication public key κ_i = g^{ζ_i} mod p.
   */
  get communicationPublicKey(): ElementModP {
    return new ElementModP(this._handle.getCommunicationPublicKey());
  }

  /**
   * Generate all key material for one guardian.
   *
   * @param guardianIndex Guardian index i (1-based by convention).
   * @param quorum        Threshold k: the number of polynomial coefficients.
   */
  static async generate(
    guardianIndex: number,
    quorum: number
  ): Promise<GuardianKeySet> {
    const result = (await getInstance()).GuardianKeySet.generate(
      guardianIndex,
      quorum
    );
    return new GuardianKeySet(result);
  }
}
