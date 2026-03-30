#include "electionguard/guardian.hpp"

#include "electionguard/constants.h"
#include "electionguard/group.hpp"
#include "electionguard/hash.hpp"
#include "electionguard/kdf.hpp"
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
#pragma region DecryptedShare

    struct DecryptedShare::Impl {
        unique_ptr<ElementModQ> voteShare;
        unique_ptr<ElementModQ> dataShare;

        Impl(unique_ptr<ElementModQ> vs, unique_ptr<ElementModQ> ds)
            : voteShare(move(vs)), dataShare(move(ds))
        {
        }
    };

    DecryptedShare::DecryptedShare(unique_ptr<ElementModQ> voteShare,
                                   unique_ptr<ElementModQ> dataShare)
        : pimpl(new Impl(move(voteShare), move(dataShare)))
    {
    }

    DecryptedShare::~DecryptedShare() = default;

    ElementModQ *DecryptedShare::getVoteShare() const { return pimpl->voteShare.get(); }

    ElementModQ *DecryptedShare::getDataShare() const { return pimpl->dataShare.get(); }

#pragma endregion

// ─────────────────────────────────────────────────────────────────────────────
#pragma region EncryptedShare

    struct EncryptedShare::Impl {
        uint64_t senderIndex;
        uint64_t recipientIndex;
        unique_ptr<ElementModQ> parameterHash;
        unique_ptr<ElementModP> alpha;
        unique_ptr<ElementModP> beta;
        vector<uint8_t> encVoteShare;
        vector<uint8_t> encDataShare;
        unique_ptr<ElementModQ> proofChallenge;
        unique_ptr<ElementModQ> proofResponse;

        Impl(uint64_t sIdx, uint64_t rIdx, unique_ptr<ElementModQ> pH,
             unique_ptr<ElementModP> a, unique_ptr<ElementModP> b,
             vector<uint8_t> ev, vector<uint8_t> ed,
             unique_ptr<ElementModQ> pc, unique_ptr<ElementModQ> pr)
            : senderIndex(sIdx), recipientIndex(rIdx), parameterHash(move(pH)),
              alpha(move(a)), beta(move(b)), encVoteShare(move(ev)), encDataShare(move(ed)),
              proofChallenge(move(pc)), proofResponse(move(pr))
        {
        }
    };

    EncryptedShare::EncryptedShare(uint64_t senderIndex, uint64_t recipientIndex,
                                   unique_ptr<ElementModQ> parameterHash,
                                   unique_ptr<ElementModP> alpha, unique_ptr<ElementModP> beta,
                                   vector<uint8_t> encVoteShare, vector<uint8_t> encDataShare,
                                   unique_ptr<ElementModQ> proofChallenge,
                                   unique_ptr<ElementModQ> proofResponse)
        : pimpl(new Impl(senderIndex, recipientIndex, move(parameterHash), move(alpha), move(beta),
                         move(encVoteShare), move(encDataShare), move(proofChallenge),
                         move(proofResponse)))
    {
    }

    EncryptedShare::~EncryptedShare() = default;

    uint64_t EncryptedShare::getSenderIndex() const { return pimpl->senderIndex; }

    uint64_t EncryptedShare::getRecipientIndex() const { return pimpl->recipientIndex; }

    const ElementModQ *EncryptedShare::getParameterHash() const
    {
        return pimpl->parameterHash.get();
    }

    const ElementModP *EncryptedShare::getAlpha() const { return pimpl->alpha.get(); }

    const ElementModP *EncryptedShare::getBeta() const { return pimpl->beta.get(); }

    const vector<uint8_t> &EncryptedShare::getEncVoteShare() const { return pimpl->encVoteShare; }

    const vector<uint8_t> &EncryptedShare::getEncDataShare() const { return pimpl->encDataShare; }

    bool EncryptedShare::isProofValid(const ElementModQ *parameterHash,
                                      const ElementModP *recipientCommKey) const
    {
        const uint64_t i = pimpl->senderIndex;
        const uint64_t l = pimpl->recipientIndex;

        // h' = g^v * alpha^c mod p
        auto gv = g_pow_p(*pimpl->proofResponse);
        auto alphac = pow_mod_p(*pimpl->alpha, *pimpl->proofChallenge);
        auto h_prime = mul_mod_p(*gv, *alphac);

        // c' = H_q(H_P; 0x12, i, l, kappa_l, alpha, beta, h')
        vector<CryptoHashableType> args;
        args.push_back(static_cast<uint64_t>(i));
        args.push_back(static_cast<uint64_t>(l));
        args.push_back(const_cast<ElementModP *>(recipientCommKey));
        args.push_back(const_cast<ElementModP *>(pimpl->alpha.get()));
        args.push_back(const_cast<ElementModP *>(pimpl->beta.get()));
        args.push_back(h_prime.get());

        auto c_prime = hash_elems_v21_q(parameterHash, EG_DS_SHARE_ENC_PROOF, args);
        return *c_prime == *pimpl->proofChallenge;
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

        // ── Polynomial evaluation ──────────────────────────────────────────────
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

        // ── Proof generation ───────────────────────────────────────────────────
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

        // ── Share encryption helper ────────────────────────────────────────────

        // Pad or truncate `bytes` to exactly `targetLen` bytes (big-endian, leading zeros).
        static vector<uint8_t> padToSize(vector<uint8_t> bytes, size_t targetLen)
        {
            if (bytes.size() < targetLen) {
                bytes.insert(bytes.begin(), targetLen - bytes.size(), 0x00);
            } else if (bytes.size() > targetLen) {
                // Truncate from the front (keep least significant bytes)
                bytes.erase(bytes.begin(), bytes.begin() + (bytes.size() - targetLen));
            }
            return bytes;
        }

        // Build the KDF context bytes: "share_encrypt" || be32(i) || be32(l)
        static vector<uint8_t> buildKdfContext(uint64_t i, uint64_t l)
        {
            static const string ctx_prefix = "share_encrypt";
            vector<uint8_t> ctx;
            ctx.insert(ctx.end(), ctx_prefix.begin(), ctx_prefix.end());
            ctx.push_back(static_cast<uint8_t>((i >> 24) & 0xFF));
            ctx.push_back(static_cast<uint8_t>((i >> 16) & 0xFF));
            ctx.push_back(static_cast<uint8_t>((i >> 8) & 0xFF));
            ctx.push_back(static_cast<uint8_t>(i & 0xFF));
            ctx.push_back(static_cast<uint8_t>((l >> 24) & 0xFF));
            ctx.push_back(static_cast<uint8_t>((l >> 16) & 0xFF));
            ctx.push_back(static_cast<uint8_t>((l >> 8) & 0xFF));
            ctx.push_back(static_cast<uint8_t>(l & 0xFF));
            return ctx;
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

    ElementModP *GuardianKeySet::getCommunicationPublicKey() const { return getCommPublicKey(); }

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

    unique_ptr<EncryptedShare>
    GuardianKeySet::encryptShareFor(uint64_t recipientIndex, const ElementModP *recipientCommKey,
                                    const ElementModQ *parameterHash) const
    {
        const uint64_t i = pimpl->guardianIndex;
        const uint64_t l = recipientIndex;

        // 1. DH pair: xi is random, alpha = g^xi, beta = kappa_l^xi
        auto xi = rand_q();
        auto alpha = g_pow_p(*xi);
        auto beta = pow_mod_p(*recipientCommKey, *xi);

        // 2. k = H(H_P; 0x11, i, l, kappa_l, alpha, beta)
        //    Returns 32-byte raw HMAC (may be >= Q, stored unchecked)
        auto k_elem = hash_elems_v21(parameterHash, EG_DS_SHARE_ENC_KEY,
                                     {static_cast<uint64_t>(i), static_cast<uint64_t>(l),
                                      const_cast<ElementModP *>(recipientCommKey), alpha.get(),
                                      beta.get()});
        auto k_bytes = GuardianKeySetImpl::padToSize(k_elem->toBytes(), 32);

        // 3. KDF: derive two 32-byte keys
        auto context = GuardianKeySetImpl::buildKdfContext(i, l);
        auto keys = KDF::derive(k_bytes, "share_enc_keys", context, 2);
        const auto &k1 = keys[0];
        const auto &k2 = keys[1];

        // 4. Evaluate polynomials, then XOR-encrypt
        auto vote_bytes =
          GuardianKeySetImpl::padToSize(pimpl->evaluatePoly(pimpl->voteCoefficients, l)->toBytes(),
                                        32);
        auto data_bytes =
          GuardianKeySetImpl::padToSize(pimpl->evaluatePoly(pimpl->dataCoefficients, l)->toBytes(),
                                        32);

        vector<uint8_t> c_vote(32), c_data(32);
        for (size_t idx = 0; idx < 32; ++idx) {
            c_vote[idx] = vote_bytes[idx] ^ k1[idx];
            c_data[idx] = data_bytes[idx] ^ k2[idx];
        }

        // 5. Schnorr proof that sender knows xi (the DL of alpha)
        auto u = rand_q();
        auto h = g_pow_p(*u);

        auto c = hash_elems_v21_q(parameterHash, EG_DS_SHARE_ENC_PROOF,
                                  {static_cast<uint64_t>(i), static_cast<uint64_t>(l),
                                   const_cast<ElementModP *>(recipientCommKey), alpha.get(),
                                   beta.get(), h.get()});

        auto v = a_minus_bc_mod_q(*u, *c, *xi);

        return make_unique<EncryptedShare>(i, l, parameterHash->clone(), move(alpha), move(beta),
                                          move(c_vote), move(c_data), move(c), move(v));
    }

    unique_ptr<DecryptedShare>
    GuardianKeySet::decryptShareFrom(uint64_t senderIndex, const EncryptedShare &encShare) const
    {
        const uint64_t i = senderIndex;
        const uint64_t l = pimpl->guardianIndex;

        // Recompute beta = alpha^zeta_l mod p  (DH property: equals kappa_l^xi)
        auto beta = pow_mod_p(*encShare.getAlpha(), *pimpl->commSecret);

        // k = H(H_P; 0x11, i, l, kappa_l, alpha, beta)
        const ElementModQ *hp = encShare.getParameterHash();
        auto k_elem = hash_elems_v21(hp, EG_DS_SHARE_ENC_KEY,
                                     {static_cast<uint64_t>(i), static_cast<uint64_t>(l),
                                      const_cast<ElementModP *>(pimpl->commPublic.get()),
                                      const_cast<ElementModP *>(encShare.getAlpha()),
                                      beta.get()});
        auto k_bytes = GuardianKeySetImpl::padToSize(k_elem->toBytes(), 32);

        // KDF: derive two 32-byte keys
        auto context = GuardianKeySetImpl::buildKdfContext(i, l);
        auto keys = KDF::derive(k_bytes, "share_enc_keys", context, 2);
        const auto &k1 = keys[0];
        const auto &k2 = keys[1];

        // XOR-decrypt
        const auto &ev = encShare.getEncVoteShare();
        const auto &ed = encShare.getEncDataShare();

        vector<uint8_t> vote_bytes(32), data_bytes(32);
        for (size_t idx = 0; idx < 32; ++idx) {
            vote_bytes[idx] = ev[idx] ^ k1[idx];
            data_bytes[idx] = ed[idx] ^ k2[idx];
        }

        // Convert bytes back to ElementModQ (unchecked — they are polynomial evaluations mod q)
        auto vote_share = bytes_to_q(vote_bytes, true);
        auto data_share = bytes_to_q(data_bytes, true);

        return make_unique<DecryptedShare>(move(vote_share), move(data_share));
    }

    unique_ptr<ElementModP>
    GuardianKeySet::computeJointVoteKey(vector<const GuardianKeySet *> guardians)
    {
        if (guardians.empty()) {
            return nullptr;
        }
        auto K = guardians[0]->getVotePublicKey()->clone();
        for (size_t i = 1; i < guardians.size(); ++i) {
            K = mul_mod_p(*K, *guardians[i]->getVotePublicKey());
        }
        return K;
    }

    unique_ptr<ElementModP>
    GuardianKeySet::computeJointDataKey(vector<const GuardianKeySet *> guardians)
    {
        if (guardians.empty()) {
            return nullptr;
        }
        auto K_hat = guardians[0]->getDataPublicKey()->clone();
        for (size_t i = 1; i < guardians.size(); ++i) {
            K_hat = mul_mod_p(*K_hat, *guardians[i]->getDataPublicKey());
        }
        return K_hat;
    }

    unique_ptr<ElementModQ>
    GuardianKeySet::computeGuardianRecordHash(const ElementModQ *hb, const ElementModP *K,
                                              const ElementModP *K_hat,
                                              vector<const GuardianKeySet *> guardians)
    {
        vector<CryptoHashableType> args;

        // Joint vote key and joint data key
        args.push_back(const_cast<ElementModP *>(K));
        args.push_back(const_cast<ElementModP *>(K_hat));

        // All vote commitments: K_{1,0},...,K_{1,k-1}, K_{2,0},...,K_{n,k-1}
        for (const auto *guardian : guardians) {
            for (auto *commitment : guardian->getVoteCommitments()) {
                args.push_back(commitment);
            }
        }

        // All data commitments: K̂_{1,0},...,K̂_{1,k-1}, K̂_{2,0},...,K̂_{n,k-1}
        for (const auto *guardian : guardians) {
            for (auto *commitment : guardian->getDataCommitments()) {
                args.push_back(commitment);
            }
        }

        // All communication public keys: κ_1,...,κ_n
        for (const auto *guardian : guardians) {
            args.push_back(guardian->getCommPublicKey());
        }

        return hash_elems_v21(hb, EG_DS_GUARDIAN_RECORD_HASH, args);
    }

    unique_ptr<GuardianKeySet> GuardianKeySet::generate(uint64_t guardianIndex, uint64_t quorum)
    {
        // ── Vote polynomial ──────────────────────────────────────────────────
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

        // ── Data polynomial ──────────────────────────────────────────────────
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

        // ── Communication key ────────────────────────────────────────────────
        auto zeta = rand_q();
        auto kappa = g_pow_p(*zeta);

        auto impl =
          make_unique<GuardianKeySetImpl>(guardianIndex, quorum, move(voteCoeff), move(voteComm),
                                          move(dataCoeff), move(dataComm), move(zeta), move(kappa));

        return unique_ptr<GuardianKeySet>(new GuardianKeySet(move(impl)));
    }

#pragma endregion

} // namespace electionguard
