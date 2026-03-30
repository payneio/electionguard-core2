#ifndef __ELECTIONGUARD_CPP_NONCES_HPP_INCLUDED__
#define __ELECTIONGUARD_CPP_NONCES_HPP_INCLUDED__

#include "export.h"
#include "group.hpp"

#include <memory>
#include <variant>
#include <vector>

namespace electionguard
{
    using NoncesHeaderType = std::variant<ElementModP *, ElementModQ *, std::string>;

    class EG_API Nonces
    {
      public:
        Nonces(const Nonces &other);
        Nonces(const Nonces &&other);
        Nonces(const ElementModQ &seed, const NoncesHeaderType &headers);
        Nonces(const ElementModQ &seed);
        ~Nonces();

        Nonces &operator=(Nonces rhs);
        Nonces &operator=(Nonces &&rhs);

        std::unique_ptr<ElementModQ> get(uint64_t item) const;
        std::unique_ptr<ElementModQ> get(uint64_t item, std::string headers) const;
        std::vector<std::unique_ptr<ElementModQ>> get(uint64_t startItem, uint64_t count) const;
        std::unique_ptr<ElementModQ> next() const;

      private:
        struct Impl;
        std::unique_ptr<Impl> pimpl;
    };

    /// v2.1: H_I = H(H_E; 0x20, id_B) — selection encryption identifier
    EG_API std::unique_ptr<ElementModQ>
    compute_selection_encryption_id(const ElementModQ *extendedHash,
                                    const ElementModQ *ballotId);

    /// v2.1: xi_{i,j} = H_q(H_I; 0x21, i, j, xi_B) — per-selection nonce
    EG_API std::unique_ptr<ElementModQ>
    derive_selection_nonce(const ElementModQ *selectionEncId,
                           uint64_t contestIndex, uint64_t selectionIndex,
                           const ElementModQ *ballotNonce);

    /// v2.1: xi = H_q(H_I; 0x25, ind_c, xi_B) — contest data nonce
    EG_API std::unique_ptr<ElementModQ>
    derive_contest_data_nonce(const ElementModQ *selectionEncId,
                               uint64_t contestIndex,
                               const ElementModQ *ballotNonce);

} // namespace electionguard

#endif /* __ELECTIONGUARD_CPP_NONCES_HPP_INCLUDED__ */
