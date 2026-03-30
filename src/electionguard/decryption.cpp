#include "electionguard/decryption.hpp"

#include "electionguard/constants.h"
#include "electionguard/group.hpp"
#include "electionguard/hash.hpp"
#include "log.hpp"

#include <memory>
#include <stdexcept>
#include <vector>

using std::invalid_argument;
using std::make_unique;
using std::move;
using std::unique_ptr;
using std::vector;

namespace electionguard
{
#pragma region DecryptionProof

    struct DecryptionProof::Impl {
        unique_ptr<ElementModP> pad;
        unique_ptr<ElementModP> data;
        unique_ptr<ElementModQ> challenge;
        unique_ptr<ElementModQ> response;

        Impl(unique_ptr<ElementModP> pad, unique_ptr<ElementModP> data,
             unique_ptr<ElementModQ> challenge, unique_ptr<ElementModQ> response)
            : pad(move(pad)), data(move(data)), challenge(move(challenge)),
              response(move(response))
        {
        }
    };

    // Lifecycle Methods

    DecryptionProof::DecryptionProof(unique_ptr<ElementModP> pad, unique_ptr<ElementModP> data,
                                     unique_ptr<ElementModQ> challenge,
                                     unique_ptr<ElementModQ> response)
        : pimpl(new Impl(move(pad), move(data), move(challenge), move(response)))
    {
    }

    DecryptionProof::~DecryptionProof() = default;

    // Property Getters

    ElementModP *DecryptionProof::getPad() const { return pimpl->pad.get(); }
    ElementModP *DecryptionProof::getData() const { return pimpl->data.get(); }
    ElementModQ *DecryptionProof::getChallenge() const { return pimpl->challenge.get(); }
    ElementModQ *DecryptionProof::getResponse() const { return pimpl->response.get(); }

    // Static Methods

    unique_ptr<ElementModQ> DecryptionProof::computeCommitmentHash(
        const ElementModQ *extendedHash, uint64_t contestIndex, uint64_t selectionIndex,
        uint64_t guardianIndex, const ElementModP *A, const ElementModP *B,
        const ElementModP *a_i, const ElementModP *b_i, const ElementModP *M_i,
        const vector<uint64_t> &availableGuardians)
    {
        auto args = vector<CryptoHashableType>();
        args.push_back(contestIndex);
        args.push_back(selectionIndex);
        args.push_back(guardianIndex);
        args.push_back(const_cast<ElementModP *>(A));
        args.push_back(const_cast<ElementModP *>(B));
        args.push_back(const_cast<ElementModP *>(a_i));
        args.push_back(const_cast<ElementModP *>(b_i));
        args.push_back(const_cast<ElementModP *>(M_i));
        args.push_back(static_cast<uint64_t>(availableGuardians.size()));
        for (auto idx : availableGuardians) {
            args.push_back(idx);
        }
        return hash_elems_v21(extendedHash, EG_DS_TALLY_DECRYPT_COMMIT, args);
    }

    unique_ptr<ElementModQ> DecryptionProof::computeDecryptionChallenge(
        const ElementModQ *extendedHash, uint64_t contestIndex, uint64_t selectionIndex,
        const ElementModP *A, const ElementModP *B, const ElementModP *a, const ElementModP *b,
        const ElementModP *M)
    {
        return hash_elems_v21_q(extendedHash, EG_DS_TALLY_DECRYPT_PROOF,
                                {contestIndex, selectionIndex, const_cast<ElementModP *>(A),
                                 const_cast<ElementModP *>(B), const_cast<ElementModP *>(a),
                                 const_cast<ElementModP *>(b), const_cast<ElementModP *>(M)});
    }

    unique_ptr<ElementModQ> DecryptionProof::computeContestDataCommitmentHash(
        const ElementModQ *selectionEncId,
        uint64_t contestIndex, uint64_t guardianIndex,
        const ElementModP *C0, const vector<uint8_t> &C1, const vector<uint8_t> &C2,
        const ElementModP *a_i, const ElementModP *b_i, const ElementModP *m_i,
        const vector<uint64_t> &availableGuardians)
    {
        vector<CryptoHashableType> args;
        args.push_back(contestIndex);
        args.push_back(guardianIndex);
        args.push_back(const_cast<ElementModP *>(C0));
        args.push_back(C1);
        args.push_back(C2);
        args.push_back(const_cast<ElementModP *>(a_i));
        args.push_back(const_cast<ElementModP *>(b_i));
        args.push_back(const_cast<ElementModP *>(m_i));
        args.push_back(static_cast<uint64_t>(availableGuardians.size()));
        for (auto idx : availableGuardians) {
            args.push_back(idx);
        }
        return hash_elems_v21(selectionEncId, EG_DS_CONTEST_DECRYPT_COMMIT, args);
    }

    unique_ptr<ElementModQ> DecryptionProof::computeContestDataDecryptionChallenge(
        const ElementModQ *selectionEncId,
        uint64_t contestIndex,
        const ElementModP *C0, const vector<uint8_t> &C1, const vector<uint8_t> &C2,
        const ElementModP *a, const ElementModP *b, const ElementModP *M)
    {
        return hash_elems_v21_q(selectionEncId, EG_DS_CONTEST_DECRYPT_PROOF,
                                {contestIndex,
                                 const_cast<ElementModP *>(C0), C1, C2,
                                 const_cast<ElementModP *>(a), const_cast<ElementModP *>(b),
                                 const_cast<ElementModP *>(M)});
    }

    bool DecryptionProof::isValid(const ElGamalCiphertext &message, const ElementModP &K,
                                  const ElementModP &M, const ElementModQ &extendedHash,
                                  uint64_t contestIndex, uint64_t selectionIndex) const
    {
        // a_check = g^v * K^c mod p
        auto a_check = mul_mod_p(*g_pow_p(*getResponse()), *pow_mod_p(K, *getChallenge()));
        // b_check = A^v * M^c mod p
        auto b_check = mul_mod_p(*pow_mod_p(*message.getPad(), *getResponse()),
                                 *pow_mod_p(M, *getChallenge()));

        bool pad_ok = (*a_check == *getPad());
        bool data_ok = (*b_check == *getData());

        auto c_check = computeDecryptionChallenge(&extendedHash, contestIndex, selectionIndex,
                                                  message.getPad(), message.getData(), getPad(),
                                                  getData(), &M);

        return pad_ok && data_ok && (*c_check == *getChallenge());
    }

#pragma endregion

} // namespace electionguard
