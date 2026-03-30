#include "electionguard/ballot_code.hpp"

#include "electionguard/constants.h"
#include "electionguard/hash.hpp"
#include "log.hpp"

#include <cstring>
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

    vector<uint8_t> BallotCode::buildNoChainingField(const ElementModQ *deviceInfoHash)
    {
        vector<uint8_t> field(36, 0x00);
        // mode = 0x00000000 (first 4 bytes already zero)
        auto hdiBytes = deviceInfoHash->toBytes();
        // Pad to 32 bytes if needed
        while (hdiBytes.size() < 32) {
            hdiBytes.insert(hdiBytes.begin(), 0x00);
        }
        memcpy(field.data() + 4, hdiBytes.data(), 32);
        return field;
    }

    vector<uint8_t> BallotCode::buildSimpleChainInitField(const ElementModQ *deviceInfoHash)
    {
        vector<uint8_t> field(36, 0x00);
        field[3] = 0x01; // mode = 0x00000001
        auto hdiBytes = deviceInfoHash->toBytes();
        while (hdiBytes.size() < 32) {
            hdiBytes.insert(hdiBytes.begin(), 0x00);
        }
        memcpy(field.data() + 4, hdiBytes.data(), 32);
        return field;
    }

    vector<uint8_t> BallotCode::buildSimpleChainField(const ElementModQ *previousHash)
    {
        vector<uint8_t> field(36, 0x00);
        field[3] = 0x01;
        auto hashBytes = previousHash->toBytes();
        while (hashBytes.size() < 32) {
            hashBytes.insert(hashBytes.begin(), 0x00);
        }
        memcpy(field.data() + 4, hashBytes.data(), 32);
        return field;
    }

    unique_ptr<ElementModQ> BallotCode::computeChainInitHash(
        const ElementModQ *extendedHash, const vector<uint8_t> &initField)
    {
        return hash_elems_v21(extendedHash, EG_DS_CONFIRMATION_CODE, {initField});
    }

    unique_ptr<ElementModQ> BallotCode::closeChain(
        const ElementModQ *extendedHash,
        const ElementModQ *lastHash,
        const vector<uint8_t> &initField)
    {
        // Inner: H(H_E; 0x2B, H_last, B_{C,0})
        auto innerHash = hash_elems_v21(extendedHash, EG_DS_CHAIN_CLOSING,
                                        {const_cast<ElementModQ *>(lastHash), initField});

        // Closing field: 0x00000001 || innerHash
        auto closingField = buildSimpleChainField(innerHash.get());

        // H_bar = H(H_E; 0x29, closingField)
        return hash_elems_v21(extendedHash, EG_DS_CONFIRMATION_CODE, {closingField});
    }

} // namespace electionguard
