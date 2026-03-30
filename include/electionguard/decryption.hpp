#ifndef __ELECTIONGUARD_CPP_DECRYPTION_HPP_INCLUDED__
#define __ELECTIONGUARD_CPP_DECRYPTION_HPP_INCLUDED__

#include "elgamal.hpp"
#include "export.h"
#include "group.hpp"

#include <memory>
#include <vector>

namespace electionguard
{
    class EG_API DecryptionProof
    {
      public:
        DecryptionProof(std::unique_ptr<ElementModP> pad,
                        std::unique_ptr<ElementModP> data,
                        std::unique_ptr<ElementModQ> challenge,
                        std::unique_ptr<ElementModQ> response);
        ~DecryptionProof();

        ElementModP *getPad() const;
        ElementModP *getData() const;
        ElementModQ *getChallenge() const;
        ElementModQ *getResponse() const;

        /// v2.1 commit-to-commitment: d_i = H(H_E; 0x30, ...)
        static std::unique_ptr<ElementModQ> computeCommitmentHash(
            const ElementModQ *extendedHash,
            uint64_t contestIndex, uint64_t selectionIndex, uint64_t guardianIndex,
            const ElementModP *A, const ElementModP *B,
            const ElementModP *a_i, const ElementModP *b_i,
            const ElementModP *M_i,
            const std::vector<uint64_t> &availableGuardians);

        /// v2.1 decryption challenge: c = H_q(H_E; 0x31, ...)
        static std::unique_ptr<ElementModQ> computeDecryptionChallenge(
            const ElementModQ *extendedHash,
            uint64_t contestIndex, uint64_t selectionIndex,
            const ElementModP *A, const ElementModP *B,
            const ElementModP *a, const ElementModP *b,
            const ElementModP *M);

        /// v2.1 verification: check a = g^v * K^c, b = A^v * M^c, and challenge recomputation
        bool isValid(const ElGamalCiphertext &message, const ElementModP &K,
                     const ElementModP &M, const ElementModQ &extendedHash,
                     uint64_t contestIndex, uint64_t selectionIndex) const;

      private:
        class Impl;
#pragma warning(suppress : 4251)
        std::unique_ptr<Impl> pimpl;
    };
} // namespace electionguard

#endif /* __ELECTIONGUARD_CPP_DECRYPTION_HPP_INCLUDED__ */
