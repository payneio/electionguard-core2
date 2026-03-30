#include "electionguard/ballot_code.hpp"

#include "electionguard/constants.h"
#include "electionguard/hash.hpp"
#include "log.hpp"

#include <string>
#include <vector>

using std::string;
using std::unique_ptr;
using std::vector;

namespace electionguard
{
    unique_ptr<ElementModQ> BallotCode::getHashForDevice(uint64_t deviceUuid, uint64_t sessionUuid,
                                                         uint64_t launchCode,
                                                         const string &location)
    {
        return hash_elems({deviceUuid, sessionUuid, launchCode, location});
    }

    unique_ptr<ElementModQ> BallotCode::getBallotCode(const ElementModQ &seed, uint64_t timestamp,
                                                      const ElementModQ &ballotCode)
    {
        return hash_elems(
          {&const_cast<ElementModQ &>(seed), timestamp, &const_cast<ElementModQ &>(ballotCode)});
    }

    unique_ptr<ElementModQ> BallotCode::computeContestHash(
        const ElementModQ *selectionEncId,
        uint64_t contestIndex,
        const vector<const ElGamalCiphertext *> &selections,
        const HashedElGamalCiphertext *contestData)
    {
        vector<CryptoHashableType> args;
        args.push_back(contestIndex);
        for (auto *sel : selections) {
            args.push_back(const_cast<ElementModP *>(sel->getPad()));
            args.push_back(const_cast<ElementModP *>(sel->getData()));
        }
        if (contestData != nullptr) {
            args.push_back(const_cast<ElementModP *>(contestData->getPad()));
            args.push_back(contestData->getData());
            args.push_back(contestData->getMac());
        }
        return hash_elems_v21(selectionEncId, EG_DS_CONTEST_HASH, args);
    }

    unique_ptr<ElementModQ> BallotCode::computeDeviceInfoHash(
        const ElementModQ *extendedHash, const string &deviceInfo)
    {
        return hash_elems_v21(extendedHash, EG_DS_DEVICE_INFO_HASH, {deviceInfo});
    }

    unique_ptr<ElementModQ> BallotCode::computeConfirmationCode(
        const ElementModQ *selectionEncId,
        const vector<const ElementModQ *> &contestHashes,
        const vector<uint8_t> &chainingField)
    {
        vector<CryptoHashableType> args;
        for (auto *chi : contestHashes) {
            args.push_back(const_cast<ElementModQ *>(chi));
        }
        args.push_back(chainingField);
        return hash_elems_v21(selectionEncId, EG_DS_CONFIRMATION_CODE, args);
    }

} // namespace electionguard
