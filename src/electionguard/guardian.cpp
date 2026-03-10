#include "electionguard/guardian.hpp"

#include "electionguard/constants.h"
#include "electionguard/group.hpp"
#include "electionguard/hash.hpp"
#include "log.hpp"

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using std::make_unique;
using std::move;
using std::string;
using std::unique_ptr;
using std::vector;

namespace electionguard
{

// ─────────────────────────────────────────────────────────────────────────────
#pragma region ConsolidatedSchnorrProof

    struct ConsolidatedSchnorrProof::Impl {
        unique_ptr<ElementModQ> challenge;
        vector<unique_ptr<ElementModQ>> responses;

        Impl(unique_ptr<ElementModQ> challenge_, vector<unique_ptr<ElementModQ>> responses_)
            : challenge(move(challenge_)), responses(move(responses_))
        {
        }

        [[nodiscard]] unique_ptr<ConsolidatedSchnorrProof::Impl> clone() const
        {
            auto c = challenge->clone();
            vector<unique_ptr<ElementModQ>> r;
            r.reserve(responses.size());
            for (const auto &resp : responses) {
                r.push_back(resp->clone());
            }
            return make_unique<ConsolidatedSchnorrProof::Impl>(move(c), move(r));
        }
    };

    ConsolidatedSchnorrProof::ConsolidatedSchnorrProof(const ConsolidatedSchnorrProof &other)
        : pimpl(other.pimpl->clone())
    {
    }

    ConsolidatedSchnorrProof::ConsolidatedSchnorrProof(ConsolidatedSchnorrProof &&other)
        : pimpl(move(other.pimpl))
    {
    }

    ConsolidatedSchnorrProof::ConsolidatedSchnorrProof(unique_ptr<ElementModQ> challenge,
                                                       vector<unique_ptr<ElementModQ>> responses)
        : pimpl(new Impl(move(challenge), move(responses)))
    {
    }

    ConsolidatedSchnorrProof::~ConsolidatedSchnorrProof() = default;

    ElementModQ *ConsolidatedSchnorrProof::getChallenge() const { return pimpl->challenge.get(); }

    uint64_t ConsolidatedSchnorrProof::getResponseCount() const
    {
        return static_cast<uint64_t>(pimpl->responses.size());
    }

    ElementModQ *ConsolidatedSchnorrProof::getResponse(uint64_t index) const
    {
        if (index >= pimpl->responses.size()) {
            throw std::out_of_range("response index out of range");
        }
        return pimpl->responses[index].get();
    }

    bool ConsolidatedSchnorrProof::isValid(const ElementModQ *parameterHash,
                                           const vector<ElementModP *> &commitments,
                                           const ElementModP *communicationKey,
                                           uint64_t guardianIndex, const string &label) const
    {
        const auto k = commitments.size();
        auto *c = pimpl->challenge.get();

        // Recompute h_{i,j} = g^{v_{i,j}} * K_{i,j}^{c_i} mod p  for j < k
        // and       h_{i,k} = g^{v_{i,k}} * κ_i^{c_i}   mod p  for j == k
        vector<unique_ptr<ElementModP>> h_values;
        h_values.reserve(k + 1);

        for (uint64_t j = 0; j < k; ++j) {
            auto gv = g_pow_p(*pimpl->responses[j]);
            auto Kc = pow_mod_p(*commitments[j], *c);
            h_values.push_back(mul_mod_p(*gv, *Kc));
        }
        {
            auto gv = g_pow_p(*pimpl->responses[k]);
            auto kc = pow_mod_p(*communicationKey, *c);
            h_values.push_back(mul_mod_p(*gv, *kc));
        }

        // Rebuild the challenge args in the same order used during generation:
        //   label, i, K_{i,0}, …, K_{i,k-1}, κ_i, h_{i,0}, …, h_{i,k}
        vector<CryptoHashableType> args;
        args.reserve(2 + k + 1 + (k + 1));
        args.push_back(label);
        args.push_back(static_cast<uint64_t>(guardianIndex));
        for (auto *K : commitments) {
            args.push_back(K);
        }
        // communicationKey is const but the variant holds ElementModP*
        args.push_back(const_cast<ElementModP *>(communicationKey));
        for (const auto &h : h_values) {
            args.push_back(h.get());
        }

        auto c_prime = hash_elems_v21_q(parameterHash, EG_DS_KEY_GENERATION_NIZK, args);
        return *c_prime == *c;
    }

#pragma endregion

// ─────────────────────────────────────────────────────────────────────────────
#pragma region GuardianKeySet implementation detail

    class GuardianKeySet::GuardianKeySetImpl
    {
      public:
        uint64_t guardianIndex;
        uint64_t quorum;

        // Vote polynomial: coefficients a_{i,j}, Feldman commitments K_{i,j}
        vector<unique_ptr<ElementModQ>> voteCoefficients;
        vector<unique_ptr<ElementModP>> voteCommitments;

        // Data polynomial: coefficients â_{i,j}, Feldman commitments K̂_{i,j}
        vector<unique_ptr<ElementModQ>> dataCoefficients;
        vector<unique_ptr<ElementModP>> dataCommitments;

        // Communication key pair (ζ_i, κ_i)
        unique_ptr<ElementModQ> commSecret;
        unique_ptr<ElementModP> commPublic;

        GuardianKeySetImpl(uint64_t guardianIndex_, uint64_t quorum_,
                           vector<unique_ptr<ElementModQ>> voteCoeff,
                           vector<unique_ptr<ElementModP>> voteComm,
                           vector<unique_ptr<ElementModQ>> dataCoeff,
                           vector<unique_ptr<ElementModP>> dataComm,
                           unique_ptr<ElementModQ> zeta, unique_ptr<ElementModP> kappa)
            : guardianIndex(guardianIndex_), quorum(quorum_),
              voteCoefficients(move(voteCoeff)), voteCommitments(move(voteComm)),
              dataCoefficients(move(dataCoeff)), dataCommitments(move(dataComm)),
              commSecret(move(zeta)), commPublic(move(kappa))
        {
        }

        [[nodiscard]] unique_ptr<GuardianKeySetImpl> clone() const
        {
            vector<unique_ptr<ElementModQ>> vc, dc;
            vector<unique_ptr<ElementModP>> vcom, dcom;
            vc.reserve(voteCoefficients.size());
            dc.reserve(dataCoefficients.size());
            for (const auto &c : voteCoefficients) {
                vc.push_back(c->clone());
            }
            for (const auto &c : voteCommitments) {
                vcom.push_back(c->clone());
            }
            for (const auto &c : dataCoefficients) {
                dc.push_back(c->clone());
            }
            for (const auto &c : dataCommitments) {
                dcom.push_back(c->clone());
            }
            return make_unique<GuardianKeySetImpl>(guardianIndex, quorum, move(vc), move(vcom),
                                                   move(dc), move(dcom), commSecret->clone(),
                                                   commPublic->clone());
        }

        // ── Polynomial evaluation ──────────────────────────────────────────
        // P_i(l) = Σ_{j=0}^{k-1} a_{i,j} · l^j  mod q
        [[nodiscard]] unique_ptr<ElementModQ>
        evaluatePoly(const vector<unique_ptr<ElementModQ>> &coefficients, uint64_t l) const
        {
            auto result = ZERO_MOD_Q().clone();
            auto lPow = ElementModQ::fromUint64(1UL, true); // l^0 = 1
            auto lMod = ElementModQ::fromUint64(l, true);
            for (const auto &coeff : coefficients) {
                auto term = mul_mod_q(*coeff, *lPow);
                result = add_mod_q(*result, *term);
                lPow = mul_mod_q(*lPow, *lMod);
            }
            return result;
        }

        // ── Proof generation ──────────────────────────────────────────────
        [[nodiscard]] unique_ptr<ConsolidatedSchnorrProof>
        generateKeyProof(const ElementModQ *parameterHash,
                         const vector<unique_ptr<ElementModQ>> &coefficients,
                         const vector<unique_ptr<ElementModP>> &commitments,
                         const string &label) const
        {
            const auto k = quorum; // == coefficients.size()

            // Pick k+1 random nonces u_{i,0} … u_{i,k} and compute h_{i,j} = g^{u_{i,j}}
            vector<unique_ptr<ElementModQ>> u_values;
            vector<unique_ptr<ElementModP>> h_values;
            u_values.reserve(k + 1);
            h_values.reserve(k + 1);
            for (uint64_t j = 0; j <= k; ++j) {
                auto u = rand_q();
                auto h = g_pow_p(*u);
                u_values.push_back(move(u));
                h_values.push_back(move(h));
            }

            // c_i = H_q(H_P ; 0x10, label, i, K_{i,0}, …, K_{i,k-1}, κ_i, h_0, …, h_k)
            vector<CryptoHashableType> args;
            args.reserve(2 + k + 1 + (k + 1));
            args.push_back(label);
            args.push_back(static_cast<uint64_t>(guardianIndex));
            for (const auto &K : commitments) {
                args.push_back(K.get());
            }
            args.push_back(commPublic.get());
            for (const auto &h : h_values) {
                args.push_back(h.get());
            }

            auto c = hash_elems_v21_q(parameterHash, EG_DS_KEY_GENERATION_NIZK, args);

            // Compute responses:
            //   v_{i,j} = u_{i,j} - c_i · a_{i,j}   for j < k
            //   v_{i,k} = u_{i,k} - c_i · ζ_i
            vector<unique_ptr<ElementModQ>> responses;
            responses.reserve(k + 1);
            for (uint64_t j = 0; j < k; ++j) {
                auto v = a_minus_bc_mod_q(*u_values[j], *c, *coefficients[j]);
                responses.push_back(move(v));
            }
            {
                auto v = a_minus_bc_mod_q(*u_values[k], *c, *commSecret);
                responses.push_back(move(v));
            }

            return make_unique<ConsolidatedSchnorrProof>(move(c), move(responses));
        }
    };

#pragma endregion

// ─────────────────────────────────────────────────────────────────────────────
#pragma region GuardianKeySet

    GuardianKeySet::GuardianKeySet(unique_ptr<GuardianKeySetImpl> impl) : pimpl(move(impl)) {}

    GuardianKeySet::GuardianKeySet(const GuardianKeySet &other) : pimpl(other.pimpl->clone()) {}

    GuardianKeySet::GuardianKeySet(GuardianKeySet &&other) : pimpl(move(other.pimpl)) {}

    GuardianKeySet::~GuardianKeySet() = default;

    ElementModP *GuardianKeySet::getVotePublicKey() const
    {
        return pimpl->voteCommitments[0].get();
    }

    ElementModP *GuardianKeySet::getDataPublicKey() const
    {
        return pimpl->dataCommitments[0].get();
    }

    ElementModP *GuardianKeySet::getCommPublicKey() const { return pimpl->commPublic.get(); }

    vector<ElementModP *> GuardianKeySet::getVoteCommitments() const
    {
        vector<ElementModP *> result;
        result.reserve(pimpl->voteCommitments.size());
        for (const auto &c : pimpl->voteCommitments) {
            result.push_back(c.get());
        }
        return result;
    }

    vector<ElementModP *> GuardianKeySet::getDataCommitments() const
    {
        vector<ElementModP *> result;
        result.reserve(pimpl->dataCommitments.size());
        for (const auto &c : pimpl->dataCommitments) {
            result.push_back(c.get());
        }
        return result;
    }

    unique_ptr<ElementModQ> GuardianKeySet::evaluateVotePolynomial(uint64_t recipientIndex) const
    {
        return pimpl->evaluatePoly(pimpl->voteCoefficients, recipientIndex);
    }

    unique_ptr<ElementModQ> GuardianKeySet::evaluateDataPolynomial(uint64_t recipientIndex) const
    {
        return pimpl->evaluatePoly(pimpl->dataCoefficients, recipientIndex);
    }

    unique_ptr<ConsolidatedSchnorrProof>
    GuardianKeySet::generateVoteKeyProof(const ElementModQ *parameterHash) const
    {
        return pimpl->generateKeyProof(parameterHash, pimpl->voteCoefficients,
                                       pimpl->voteCommitments, "pk_vote");
    }

    unique_ptr<ConsolidatedSchnorrProof>
    GuardianKeySet::generateDataKeyProof(const ElementModQ *parameterHash) const
    {
        return pimpl->generateKeyProof(parameterHash, pimpl->dataCoefficients,
                                       pimpl->dataCommitments, "pk_data");
    }

    unique_ptr<GuardianKeySet> GuardianKeySet::generate(uint64_t guardianIndex, uint64_t quorum)
    {
        // ── Vote polynomial ──────────────────────────────────────────────
        vector<unique_ptr<ElementModQ>> voteCoeff;
        vector<unique_ptr<ElementModP>> voteComm;
        voteCoeff.reserve(quorum);
        voteComm.reserve(quorum);
        for (uint64_t j = 0; j < quorum; ++j) {
            auto a = rand_q();
            auto K = g_pow_p(*a);
            voteCoeff.push_back(move(a));
            voteComm.push_back(move(K));
        }

        // ── Data polynomial ──────────────────────────────────────────────
        vector<unique_ptr<ElementModQ>> dataCoeff;
        vector<unique_ptr<ElementModP>> dataComm;
        dataCoeff.reserve(quorum);
        dataComm.reserve(quorum);
        for (uint64_t j = 0; j < quorum; ++j) {
            auto a = rand_q();
            auto K = g_pow_p(*a);
            dataCoeff.push_back(move(a));
            dataComm.push_back(move(K));
        }

        // ── Communication key ────────────────────────────────────────────
        auto zeta = rand_q();
        auto kappa = g_pow_p(*zeta);

        auto impl =
          make_unique<GuardianKeySetImpl>(guardianIndex, quorum, move(voteCoeff), move(voteComm),
                                          move(dataCoeff), move(dataComm), move(zeta), move(kappa));

        return unique_ptr<GuardianKeySet>(new GuardianKeySet(move(impl)));
    }

#pragma endregion

} // namespace electionguard
