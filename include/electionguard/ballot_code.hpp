#ifndef __ELECTIONGUARD_CPP_BALLOT_CODE_HPP_INCLUDED__
#define __ELECTIONGUARD_CPP_BALLOT_CODE_HPP_INCLUDED__

#include "elgamal.hpp"
#include "export.h"
#include "group.hpp"

#include <memory>
#include <string>
#include <vector>

namespace electionguard
{
    class EG_API BallotCode
    {
      public:
        /// <summary>
        /// Get a hash for a specific device.  The hash includes several components
        /// to guarantee the uniqueness of the device, the session instance, and the election context
        ///
        /// It is up to the consuming application to convey meaning to these fields.
        ///
        /// <param name="deviceUuid">Unique identifier of device such as a hardware Id</param>
        /// <param name="sessionUuid">Unique identifier of the application's session instance,
        ///                           can be randomly generated on startup</param>
        /// <param name="launchCode">Runtime launch code associated wit ha specific election</param>
        /// <param name="location">location of device, as an arbitrary string that is meaningful
        ///                        to the external system</param>
        /// <returns>A hash of device</returns>
        /// </summary>
        static std::unique_ptr<ElementModQ> getHashForDevice(uint64_t deviceUuid,
                                                             uint64_t sessionUuid,
                                                             uint64_t launchCode,
                                                             const std::string &location);

        /// <summary>
        /// Get a ballot code based on a seed.  Useful for chaining ballots or defining higher order link strcutures.
        ///
        /// Though not required by the spec, it can be useful for some use cases to chain ballots together
        /// And prove an unbroken dataset for a specific encryption device. Typically the rotating ballot code
        /// Is seeded with the device hash and then each subsequent call consumes the ballot code of the
        /// previous encrypted ballot creating a linked hash chain between the ballots that can be traversed.
        /// Other liniking paradigms exists (such as tree strctures) and are beyond the scope of this implementation.
        ///
        /// <param name="seed">a seed such as the previous ballot code or starting hash from device</param>
        /// <param name="timestamp">Timestamp or other incrementing integer value</param>
        /// <param name="ballotCode">Hash of the ballot</param>
        /// <returns>Code</returns>
        /// </summary>
        static std::unique_ptr<ElementModQ>
        getBallotCode(const ElementModQ &seed, uint64_t timestamp, const ElementModQ &ballotCode);

        // ── v2.1 contest hash ────────────────────────────────────────

        /// v2.1: chi_l = H(H_I; 0x28, l, alpha_1, beta_1, ..., alpha_n, beta_n, [contest_data])
        static std::unique_ptr<ElementModQ> computeContestHash(
            const ElementModQ *selectionEncId,
            uint64_t contestIndex,
            const std::vector<const ElGamalCiphertext *> &selections,
            const HashedElGamalCiphertext *contestData);

        // ── v2.1 device info hash ───────────────────────────────────

        /// v2.1: H_DI = H(H_E; 0x2A, S_device)
        static std::unique_ptr<ElementModQ> computeDeviceInfoHash(
            const ElementModQ *extendedHash,
            const std::string &deviceInfo);

        // ── v2.1 confirmation code ──────────────────────────────────

        /// v2.1: H_C = H(H_I; 0x29, chi_1, ..., chi_m, B_C)
        static std::unique_ptr<ElementModQ> computeConfirmationCode(
            const ElementModQ *selectionEncId,
            const std::vector<const ElementModQ *> &contestHashes,
            const std::vector<uint8_t> &chainingField);

        // ── v2.1 chaining ───────────────────────────────────────────

        /// v2.1 no-chain: B_C = 0x00000000 || H_DI
        static std::vector<uint8_t> buildNoChainingField(const ElementModQ *deviceInfoHash);

        /// v2.1 simple-chain init: B_{C,0} = 0x00000001 || H_DI
        static std::vector<uint8_t> buildSimpleChainInitField(const ElementModQ *deviceInfoHash);

        /// v2.1 simple-chain next: B_{C,j} = 0x00000001 || H_{j-1}
        static std::vector<uint8_t> buildSimpleChainField(const ElementModQ *previousHash);

        /// v2.1 chain init hash: H_0 = H(H_E; 0x29, B_{C,0})
        static std::unique_ptr<ElementModQ> computeChainInitHash(
            const ElementModQ *extendedHash,
            const std::vector<uint8_t> &initField);

        /// v2.1 chain closing: H_bar
        static std::unique_ptr<ElementModQ> closeChain(
            const ElementModQ *extendedHash,
            const ElementModQ *lastHash,
            const std::vector<uint8_t> &initField);
    };

} // namespace electionguard

#endif /* __ELECTIONGUARD_CPP_BALLOT_CODE_HPP_INCLUDED__ */
