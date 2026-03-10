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
        /// Generate all key material for one guardian.
        ///
        /// <param name="guardianIndex">Guardian index i (1-based by convention).</param>
        /// <param name="quorum">Threshold k: the number of polynomial coefficients.</param>
        /// </summary>
        static std::unique_ptr<GuardianKeySet> generate(uint64_t guardianIndex, uint64_t quorum);

      private:
        class GuardianKeySetImpl; // forward-declare as nested class
        explicit GuardianKeySet(std::unique_ptr<GuardianKeySetImpl> pimpl);

#pragma warning(suppress : 4251)
        std::unique_ptr<GuardianKeySetImpl> pimpl;
    };

} // namespace electionguard

#endif /* __ELECTIONGUARD_CPP_GUARDIAN_HPP_INCLUDED__ */
