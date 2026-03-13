#ifndef __ELECTIONGUARD_CPP_GUARDIAN_HPP_INCLUDED__
#define __ELECTIONGUARD_CPP_GUARDIAN_HPP_INCLUDED__

#include "export.h"
#include "group.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace electionguard
{
    /// <summary>
    /// A consolidated Schnorr proof covering all polynomial coefficients plus
    /// the communication key for a single guardian.  One challenge value c_i
    /// binds quorum+1 responses: one per polynomial coefficient (j = 0..k-1)
    /// and one for the communication secret (j = k).
    /// </summary>
    class EG_API ConsolidatedSchnorrProof
    {
      public:
        ConsolidatedSchnorrProof(const ConsolidatedSchnorrProof &other);
        ConsolidatedSchnorrProof(ConsolidatedSchnorrProof &&other);
        ConsolidatedSchnorrProof(std::unique_ptr<ElementModQ> challenge,
                                 std::vector<std::unique_ptr<ElementModQ>> responses);
        ~ConsolidatedSchnorrProof();

        /// <Summary>The single Fiat–Shamir challenge c_i.</Summary>
        ElementModQ *getChallenge() const;

        /// <Summary>Total number of responses (quorum + 1).</Summary>
        uint64_t getResponseCount() const;

        /// <Summary>Response v_{i,index}.</Summary>
        ElementModQ *getResponse(uint64_t index) const;

        /// <summary>
        /// Verify the proof by recomputing the commitment values and the challenge.
        ///
        /// <param name="parameterHash">H_P — the v2.1 parameter hash used as HMAC key.</param>
        /// <param name="commitments">Feldman commitments K_{i,0} … K_{i,k-1}.</param>
        /// <param name="communicationKey">Communication public key kappa_i.</param>
        /// <param name="guardianIndex">Guardian index i (uint64, serialised as 4 bytes).</param>
        /// <param name="label">"pk_vote" or "pk_data" — domain label embedded in the hash.</param>
        /// <returns>true iff the proof is valid.</returns>
        /// </summary>
        bool isValid(const ElementModQ *parameterHash,
                     const std::vector<ElementModP *> &commitments,
                     const ElementModP *communicationKey, uint64_t guardianIndex,
                     const std::string &label) const;

      private:
        class Impl;
#pragma warning(suppress : 4251)
        std::unique_ptr<Impl> pimpl;
    };

    /// <summary>
    /// The plaintext polynomial shares (vote and data) decrypted from an EncryptedShare.
    /// </summary>
    class EG_API DecryptedShare
    {
      public:
        DecryptedShare(std::unique_ptr<ElementModQ> voteShare,
                       std::unique_ptr<ElementModQ> dataShare);
        ~DecryptedShare();

        /// <Summary>The vote polynomial evaluation P_i(l) mod q.</Summary>
        ElementModQ *getVoteShare() const;

        /// <Summary>The data polynomial evaluation P_hat_i(l) mod q.</Summary>
        ElementModQ *getDataShare() const;

      private:
        class Impl;
#pragma warning(suppress : 4251)
        std::unique_ptr<Impl> pimpl;
    };

    /// <summary>
    /// An encrypted secret share sent from guardian i to guardian l, as per v2.1 §3.2.2.
    /// Contains the DH ephemeral pair (alpha, beta), the XOR-encrypted share values,
    /// and a Schnorr proof that the sender knows the ephemeral exponent xi.
    /// </summary>
    class EG_API EncryptedShare
    {
      public:
        EncryptedShare(uint64_t senderIndex, uint64_t recipientIndex,
                       std::unique_ptr<ElementModQ> parameterHash,
                       std::unique_ptr<ElementModP> alpha, std::unique_ptr<ElementModP> beta,
                       std::vector<uint8_t> encVoteShare, std::vector<uint8_t> encDataShare,
                       std::unique_ptr<ElementModQ> proofChallenge,
                       std::unique_ptr<ElementModQ> proofResponse);
        ~EncryptedShare();

        /// <Summary>Sender guardian index i.</Summary>
        uint64_t getSenderIndex() const;

        /// <Summary>Recipient guardian index l.</Summary>
        uint64_t getRecipientIndex() const;

        /// <Summary>H_P stored for decryption use.</Summary>
        const ElementModQ *getParameterHash() const;

        /// <Summary>Ephemeral DH public key alpha = g^xi mod p.</Summary>
        const ElementModP *getAlpha() const;

        /// <Summary>DH shared secret base beta = kappa_l^xi mod p.</Summary>
        const ElementModP *getBeta() const;

        /// <Summary>XOR-encrypted vote share (32 bytes).</Summary>
        const std::vector<uint8_t> &getEncVoteShare() const;

        /// <Summary>XOR-encrypted data share (32 bytes).</Summary>
        const std::vector<uint8_t> &getEncDataShare() const;

        /// <summary>
        /// Verify the Schnorr proof that the sender knows xi (the DL of alpha).
        ///
        /// Reconstructs h' = g^v * alpha^c, then checks that
        /// H_q(H_P; 0x12, i, l, kappa_l, alpha, beta, h') == c.
        /// </summary>
        /// <param name="parameterHash">H_P (independently supplied by the verifier).</param>
        /// <param name="recipientCommKey">kappa_l — recipient communication public key.</param>
        bool isProofValid(const ElementModQ *parameterHash,
                          const ElementModP *recipientCommKey) const;

      private:
        class Impl;
#pragma warning(suppress : 4251)
        std::unique_ptr<Impl> pimpl;
    };

    /// <summary>
    /// All key material produced during a v2.1 guardian key ceremony:
    ///   • vote key pair  (s_i,  K_i  = g^{s_i})   with degree-(k-1) Feldman polynomial
    ///   • data key pair  (ŝ_i,  K̂_i  = g^{ŝ_i})   with degree-(k-1) Feldman polynomial
    ///   • communication key pair (ζ_i, κ_i = g^{ζ_i})
    /// </summary>
    class EG_API GuardianKeySet
    {
      public:
        GuardianKeySet(const GuardianKeySet &other);
        GuardianKeySet(GuardianKeySet &&other);
        ~GuardianKeySet();

        /// <Summary>Vote public key K_i = g^{s_i} mod p (= voteCommitments[0]).</Summary>
        ElementModP *getVotePublicKey() const;

        /// <Summary>Data public key K̂_i = g^{ŝ_i} mod p (= dataCommitments[0]).</Summary>
        ElementModP *getDataPublicKey() const;

        /// <Summary>Communication public key κ_i = g^{ζ_i} mod p.</Summary>
        ElementModP *getCommPublicKey() const;

        /// <Summary>Communication public key κ_i = g^{ζ_i} mod p (alias for getCommPublicKey).</Summary>
        ElementModP *getCommunicationPublicKey() const;

        /// <Summary>Feldman commitments for the vote polynomial: K_{i,0} … K_{i,k-1}.</Summary>
        std::vector<ElementModP *> getVoteCommitments() const;

        /// <Summary>Feldman commitments for the data polynomial: K̂_{i,0} … K̂_{i,k-1}.</Summary>
        std::vector<ElementModP *> getDataCommitments() const;

        /// <Summary>Evaluate the vote polynomial at recipientIndex l: P_i(l) mod q.</Summary>
        std::unique_ptr<ElementModQ> evaluateVotePolynomial(uint64_t recipientIndex) const;

        /// <Summary>Evaluate the data polynomial at recipientIndex l: P̂_i(l) mod q.</Summary>
        std::unique_ptr<ElementModQ> evaluateDataPolynomial(uint64_t recipientIndex) const;

        /// <summary>
        /// Generate a consolidated Schnorr proof for the vote polynomial + comm key.
        /// The label embedded in the challenge hash is "pk_vote".
        /// </summary>
        std::unique_ptr<ConsolidatedSchnorrProof>
        generateVoteKeyProof(const ElementModQ *parameterHash) const;

        /// <summary>
        /// Generate a consolidated Schnorr proof for the data polynomial + comm key.
        /// The label embedded in the challenge hash is "pk_data".
        /// </summary>
        std::unique_ptr<ConsolidatedSchnorrProof>
        generateDataKeyProof(const ElementModQ *parameterHash) const;

        /// <summary>
        /// Encrypt this guardian's secret shares for recipient guardian l.
        ///
        /// Implements v2.1 §3.2.2 share encryption:
        ///   1. Generates ephemeral DH pair (alpha = g^xi, beta = kappa_l^xi)
        ///   2. Derives shared secret k = H(H_P; 0x11, i, l, kappa_l, alpha, beta)
        ///   3. Uses SP 800-108r1 KDF to derive two 32-byte keys
        ///   4. XOR-encrypts P_i(l) and P_hat_i(l)
        ///   5. Attaches a Schnorr proof that the sender knows xi
        ///
        /// <param name="recipientIndex">Recipient guardian index l.</param>
        /// <param name="recipientCommKey">kappa_l — recipient communication public key.</param>
        /// <param name="parameterHash">H_P — the v2.1 parameter hash.</param>
        /// <returns>EncryptedShare containing (alpha, beta, c_vote, c_data, proof).</returns>
        /// </summary>
        std::unique_ptr<EncryptedShare> encryptShareFor(uint64_t recipientIndex,
                                                        const ElementModP *recipientCommKey,
                                                        const ElementModQ *parameterHash) const;

        /// <summary>
        /// Decrypt a secret share addressed to this guardian.
        ///
        /// Recomputes beta = alpha^zeta_i, derives the same shared secret and KDF keys,
        /// then XOR-decrypts the share values.
        ///
        /// <param name="senderIndex">Sender guardian index i.</param>
        /// <param name="encShare">The encrypted share from guardian i.</param>
        /// <returns>DecryptedShare containing P_i(l) and P_hat_i(l).</returns>
        /// </summary>
        std::unique_ptr<DecryptedShare> decryptShareFrom(uint64_t senderIndex,
                                                         const EncryptedShare &encShare) const;

        /// <summary>
        /// Generate all key material for one guardian.
        ///
        /// <param name="guardianIndex">Guardian index i (1-based by convention).</param>
        /// <param name="quorum">Threshold k: the number of polynomial coefficients.</param>
        /// </summary>
        static std::unique_ptr<GuardianKeySet> generate(uint64_t guardianIndex, uint64_t quorum);

        /// <summary>
        /// Compute the joint vote public key K = ∏ K_i mod p.
        /// </summary>
        static std::unique_ptr<ElementModP>
        computeJointVoteKey(std::vector<const GuardianKeySet *> guardians);

        /// <summary>
        /// Compute the joint data public key K̂ = ∏ K̂_i mod p.
        /// </summary>
        static std::unique_ptr<ElementModP>
        computeJointDataKey(std::vector<const GuardianKeySet *> guardians);

        /// <summary>
        /// Compute the guardian record hash
        /// H_G = H(H_B; 0x13, K, K̂, K_{1,0},…,K_{n,k-1},
        ///                      K̂_{1,0},…,K̂_{n,k-1}, κ_1,…,κ_n).
        ///
        /// <param name="hb">H_B — election base hash (HMAC key).</param>
        /// <param name="K">Joint vote public key.</param>
        /// <param name="K_hat">Joint data public key.</param>
        /// <param name="guardians">All guardian key sets in order.</param>
        /// </summary>
        static std::unique_ptr<ElementModQ>
        computeGuardianRecordHash(const ElementModQ *hb, const ElementModP *K,
                                  const ElementModP *K_hat,
                                  std::vector<const GuardianKeySet *> guardians);

      private:
        class GuardianKeySetImpl; // forward-declare as nested class
        explicit GuardianKeySet(std::unique_ptr<GuardianKeySetImpl> pimpl);

#pragma warning(suppress : 4251)
        std::unique_ptr<GuardianKeySetImpl> pimpl;
    };

} // namespace electionguard

#endif /* __ELECTIONGUARD_CPP_GUARDIAN_HPP_INCLUDED__ */
