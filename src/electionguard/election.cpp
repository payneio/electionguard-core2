#include "electionguard/election.hpp"

#include "electionguard/constants.h"
#include "electionguard/hash.hpp"
#include "log.hpp"
#include "serialize.hpp"
#include "utils.hpp"

#include <cstring>
#include <iostream>
#include <utility>

using std::make_unique;
using std::map;
using std::move;
using std::out_of_range;
using std::ref;
using std::reference_wrapper;
using std::runtime_error;
using std::string;
using std::to_string;
using std::unique_ptr;
using std::unordered_map;
using std::vector;
using std::chrono::system_clock;

using ContextSerializer = electionguard::Serialize::CiphertextElectionContext;

namespace electionguard
{

#pragma region CiphertextElectionContext

    struct CiphertextElectionContext::Impl {
        uint64_t numberOfGuardians;
        uint64_t quorum;
        unique_ptr<ElementModP> elGamalPublicKey;
        unique_ptr<ElementModQ> commitmentHash;
        unique_ptr<ElementModQ> manifestHash;
        unique_ptr<ElementModQ> cryptoBaseHash;
        unique_ptr<ElementModQ> cryptoExtendedBaseHash;
        unordered_map<string, string> extendedData;
        unique_ptr<ContextConfiguration> configuration;
        // v2.1: ballot data public key K_hat (nullptr for legacy contexts)
        unique_ptr<ElementModP> ballotDataPublicKey;

        Impl(uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
             unique_ptr<ElementModQ> commitmentHash, unique_ptr<ElementModQ> manifestHash,
             unique_ptr<ElementModQ> cryptoBaseHash, unique_ptr<ElementModQ> cryptoExtendedBaseHash)
            : elGamalPublicKey(move(elGamalPublicKey)), commitmentHash(move(commitmentHash)),
              manifestHash(move(manifestHash)), cryptoBaseHash(move(cryptoBaseHash)),
              cryptoExtendedBaseHash(move(cryptoExtendedBaseHash))
        {
            this->numberOfGuardians = numberOfGuardians;
            this->quorum = quorum;
            this->extendedData = {};
            this->configuration = make_unique<ContextConfiguration>();
        }

        Impl(uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
             unique_ptr<ElementModQ> commitmentHash, unique_ptr<ElementModQ> manifestHash,
             unique_ptr<ElementModQ> cryptoBaseHash, unique_ptr<ElementModQ> cryptoExtendedBaseHash,
             unique_ptr<ContextConfiguration> config)
            : Impl(numberOfGuardians, quorum, move(elGamalPublicKey), move(commitmentHash),
                   move(manifestHash), move(cryptoBaseHash), move(cryptoExtendedBaseHash))

        {
            this->numberOfGuardians = numberOfGuardians;
            this->quorum = quorum;
            this->extendedData = {};
            this->configuration = move(config);
        }

        Impl(uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
             unique_ptr<ElementModQ> commitmentHash, unique_ptr<ElementModQ> manifestHash,
             unique_ptr<ElementModQ> cryptoBaseHash, unique_ptr<ElementModQ> cryptoExtendedBaseHash,
             unordered_map<string, string> extendedData)
            : elGamalPublicKey(move(elGamalPublicKey)), commitmentHash(move(commitmentHash)),
              manifestHash(move(manifestHash)), cryptoBaseHash(move(cryptoBaseHash)),
              cryptoExtendedBaseHash(move(cryptoExtendedBaseHash)), extendedData(move(extendedData))
        {
            this->numberOfGuardians = numberOfGuardians;
            this->quorum = quorum;
            this->configuration = make_unique<ContextConfiguration>();
        }

        Impl(uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
             unique_ptr<ElementModQ> commitmentHash, unique_ptr<ElementModQ> manifestHash,
             unique_ptr<ElementModQ> cryptoBaseHash, unique_ptr<ElementModQ> cryptoExtendedBaseHash,
             unique_ptr<ContextConfiguration> config, unordered_map<string, string> extendedData)
            : Impl(numberOfGuardians, quorum, move(elGamalPublicKey), move(commitmentHash),
                   move(manifestHash), move(cryptoBaseHash), move(cryptoExtendedBaseHash),
                   move(extendedData))
        {
            this->numberOfGuardians = numberOfGuardians;
            this->quorum = quorum;
            this->configuration = move(config);
        }

        // v2.1 dual-key constructor
        Impl(uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
             unique_ptr<ElementModP> ballotDataPublicKey,
             unique_ptr<ElementModQ> cryptoBaseHash, unique_ptr<ElementModQ> cryptoExtendedBaseHash)
            : elGamalPublicKey(move(elGamalPublicKey)),
              ballotDataPublicKey(move(ballotDataPublicKey)),
              cryptoBaseHash(move(cryptoBaseHash)),
              cryptoExtendedBaseHash(move(cryptoExtendedBaseHash))
        {
            this->numberOfGuardians = numberOfGuardians;
            this->quorum = quorum;
            this->extendedData = {};
            this->configuration = make_unique<ContextConfiguration>();
        }
    };

    // Lifecycle Methods

    CiphertextElectionContext::CiphertextElectionContext(
      uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
      unique_ptr<ElementModQ> commitmentHash, unique_ptr<ElementModQ> manifestHash,
      unique_ptr<ElementModQ> cryptoBaseHash, unique_ptr<ElementModQ> cryptoExtendedBaseHash)
        : pimpl(new Impl(numberOfGuardians, quorum, move(elGamalPublicKey), move(commitmentHash),
                         move(manifestHash), move(cryptoBaseHash), move(cryptoExtendedBaseHash)))
    {
    }
    CiphertextElectionContext::CiphertextElectionContext(
      uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
      unique_ptr<ElementModQ> commitmentHash, unique_ptr<ElementModQ> manifestHash,
      unique_ptr<ElementModQ> cryptoBaseHash, unique_ptr<ElementModQ> cryptoExtendedBaseHash,
      unique_ptr<ContextConfiguration> config)
        : pimpl(new Impl(numberOfGuardians, quorum, move(elGamalPublicKey), move(commitmentHash),
                         move(manifestHash), move(cryptoBaseHash), move(cryptoExtendedBaseHash),
                         move(config)))
    {
    }
    CiphertextElectionContext::CiphertextElectionContext(
      uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
      unique_ptr<ElementModQ> commitmentHash, unique_ptr<ElementModQ> manifestHash,
      unique_ptr<ElementModQ> cryptoBaseHash, unique_ptr<ElementModQ> cryptoExtendedBaseHash,
      unordered_map<string, string> extendedData)
        : pimpl(new Impl(numberOfGuardians, quorum, move(elGamalPublicKey), move(commitmentHash),
                         move(manifestHash), move(cryptoBaseHash), move(cryptoExtendedBaseHash),
                         move(extendedData)))
    {
    }
    CiphertextElectionContext::CiphertextElectionContext(
      uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
      unique_ptr<ElementModQ> commitmentHash, unique_ptr<ElementModQ> manifestHash,
      unique_ptr<ElementModQ> cryptoBaseHash, unique_ptr<ElementModQ> cryptoExtendedBaseHash,
      unique_ptr<ContextConfiguration> config, unordered_map<string, string> extendedData)
        : pimpl(new Impl(numberOfGuardians, quorum, move(elGamalPublicKey), move(commitmentHash),
                         move(manifestHash), move(cryptoBaseHash), move(cryptoExtendedBaseHash),
                         move(config), move(extendedData)))
    {
    }
    // v2.1 dual-key constructor
    CiphertextElectionContext::CiphertextElectionContext(
      uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
      unique_ptr<ElementModP> ballotDataPublicKey, unique_ptr<ElementModQ> cryptoBaseHash,
      unique_ptr<ElementModQ> cryptoExtendedBaseHash)
        : pimpl(new Impl(numberOfGuardians, quorum, move(elGamalPublicKey),
                         move(ballotDataPublicKey), move(cryptoBaseHash),
                         move(cryptoExtendedBaseHash)))
    {
    }

    CiphertextElectionContext::~CiphertextElectionContext() = default;

    // Operator Overloads

    CiphertextElectionContext &CiphertextElectionContext::operator=(CiphertextElectionContext other)
    {
        swap(pimpl, other.pimpl);
        return *this;
    }

    // Property Getters
    const ContextConfiguration *CiphertextElectionContext::getConfiguration() const
    {
        return pimpl->configuration.get();
    }

    uint64_t CiphertextElectionContext::getNumberOfGuardians() const
    {
        return pimpl->numberOfGuardians;
    }
    uint64_t CiphertextElectionContext::getQuorum() const { return pimpl->quorum; }
    const ElementModP *CiphertextElectionContext::getElGamalPublicKey() const
    {
        return pimpl->elGamalPublicKey.get();
    }
    const ElementModP &CiphertextElectionContext::getElGamalPublicKeyRef() const
    {
        return *pimpl->elGamalPublicKey.get();
    }
    const ElementModQ *CiphertextElectionContext::getCommitmentHash() const
    {
        return pimpl->commitmentHash.get();
    }
    const ElementModQ *CiphertextElectionContext::getManifestHash() const
    {
        return pimpl->manifestHash.get();
    }
    const ElementModQ *CiphertextElectionContext::getCryptoBaseHash() const
    {
        return pimpl->cryptoBaseHash.get();
    }
    const ElementModQ *CiphertextElectionContext::getCryptoExtendedBaseHash() const
    {
        return pimpl->cryptoExtendedBaseHash.get();
    }

    const ElementModP *CiphertextElectionContext::getBallotDataPublicKey() const
    {
        return pimpl->ballotDataPublicKey.get();
    }

    const unordered_map<string, string> CiphertextElectionContext::getExtendedData() const
    {
        return pimpl->extendedData;
    }

    // Public Methods

    vector<uint8_t> CiphertextElectionContext::toBson() const
    {
        return ContextSerializer::toBson(*this);
    }

    string CiphertextElectionContext::toJson() const { return ContextSerializer::toJson(*this); }

    unique_ptr<CiphertextElectionContext> CiphertextElectionContext::fromJson(string data)
    {
        return ContextSerializer::fromJson(move(data));
    }

    unique_ptr<CiphertextElectionContext> CiphertextElectionContext::fromBson(vector<uint8_t> data)
    {
        return ContextSerializer::fromBson(move(data));
    }

    // Public Static Methods

    unique_ptr<CiphertextElectionContext> CiphertextElectionContext::make(
      uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
      unique_ptr<ElementModQ> commitmentHash, unique_ptr<ElementModQ> manifestHash)
    {
        // TODO: configurable version code

        // HP = H(HV ;00,p,q,g). Parameter Hash 3.1.2
        auto versionCode = string_to_fixed_width_bytes<32>("v2.0");
        auto parameterHash = hash_elems(
          {versionCode, HashPrefix::get_prefix_parameter_hash(), &const_cast<ElementModP &>(P()),
           &const_cast<ElementModQ &>(Q()), &const_cast<ElementModP &>(G())});

        // HM = H(HP;01,manifest). Manifest Hash 3.1.4
        auto manifestDigest = hash_elems(
          {parameterHash.get(), HashPrefix::get_prefix_manifest_hash(), manifestHash.get()});

        // HB =(HP;02,n,k,date,info,HM). Election Base Hash 3.1.5
        auto cryptoBaseHash = hash_elems({parameterHash.get(), HashPrefix::get_prefix_base_hash(),
                                          manifestDigest.get(), numberOfGuardians, quorum});

        // HE = H(HB;12,K,K1,0,K1,1,...,K1,k−1,K2,0,...,Kn,k−2,Kn,k−1). // Extended Base Hash 3.2.3
        auto cryptoExtendedBaseHash =
          hash_elems({cryptoBaseHash.get(), HashPrefix::get_prefix_extended_hash(),
                      elGamalPublicKey.get(), commitmentHash.get()});

        // ensure the elgamal public key instance is set as a fixed base
        elGamalPublicKey->setIsFixedBase(true);

        return make_unique<CiphertextElectionContext>(
          numberOfGuardians, quorum, move(elGamalPublicKey), move(commitmentHash),
          move(manifestHash), move(cryptoBaseHash), move(cryptoExtendedBaseHash));
    }

    unique_ptr<CiphertextElectionContext> CiphertextElectionContext::make(
      uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
      unique_ptr<ElementModQ> commitmentHash, unique_ptr<ElementModQ> manifestHash,
      unique_ptr<ContextConfiguration> config)
    {
        // TODO: configurable version code

        // HP = H(HV ;00,p,q,g). Parameter Hash 3.1.2
        auto versionCode = string_to_fixed_width_bytes<32>("v2.0");
        auto parameterHash = hash_elems(
          {versionCode, HashPrefix::get_prefix_parameter_hash(), &const_cast<ElementModP &>(P()),
           &const_cast<ElementModQ &>(Q()), &const_cast<ElementModP &>(G())});

        // HM = H(HP;01,manifest). Manifest Hash 3.1.4
        auto manifestDigest = hash_elems(
          {parameterHash.get(), HashPrefix::get_prefix_manifest_hash(), manifestHash.get()});

        // TODO: complete according to spec
        // HB =(HP;02,n,k,date,info,HM). Election Base Hash 3.1.5
        auto cryptoBaseHash = hash_elems({parameterHash.get(), HashPrefix::get_prefix_base_hash(),
                                          manifestDigest.get(), numberOfGuardians, quorum});

        // HE = H(HB;12,K,K1,0,K1,1,...,K1,k−1,K2,0,...,Kn,k−2,Kn,k−1). // Extended Base Hash 3.2.3
        auto cryptoExtendedBaseHash =
          hash_elems({cryptoBaseHash.get(), HashPrefix::get_prefix_extended_hash(),
                      elGamalPublicKey.get(), commitmentHash.get()});

        // ensure the elgamal public key instance is set as a fixed base
        elGamalPublicKey->setIsFixedBase(true);

        return make_unique<CiphertextElectionContext>(
          numberOfGuardians, quorum, move(elGamalPublicKey), move(commitmentHash),
          move(manifestHash), move(cryptoBaseHash), move(cryptoExtendedBaseHash), move(config));
    }

    unique_ptr<CiphertextElectionContext> CiphertextElectionContext::make(
      uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
      unique_ptr<ElementModQ> commitmentHash, unique_ptr<ElementModQ> manifestHash,
      std::unordered_map<std::string, std::string> extendedData)
    {
        // TODO: configurable version code

        // HP = H(HV ;00,p,q,g). Parameter Hash 3.1.2
        auto versionCode = string_to_fixed_width_bytes<32>("v2.0");
        auto parameterHash = hash_elems(
          {versionCode, HashPrefix::get_prefix_parameter_hash(), &const_cast<ElementModP &>(P()),
           &const_cast<ElementModQ &>(Q()), &const_cast<ElementModP &>(G())});

        // HM = H(HP;01,manifest). Manifest Hash 3.1.4
        auto manifestDigest = hash_elems(
          {parameterHash.get(), HashPrefix::get_prefix_manifest_hash(), manifestHash.get()});

        // TODO: complete according to spec
        // HB =(HP;02,n,k,date,info,HM). Election Base Hash 3.1.5
        auto cryptoBaseHash = hash_elems({parameterHash.get(), HashPrefix::get_prefix_base_hash(),
                                          manifestDigest.get(), numberOfGuardians, quorum});

        // HE = H(HB;12,K,K1,0,K1,1,...,K1,k−1,K2,0,...,Kn,k−2,Kn,k−1). // Extended Base Hash 3.2.3
        auto cryptoExtendedBaseHash =
          hash_elems({cryptoBaseHash.get(), HashPrefix::get_prefix_extended_hash(),
                      elGamalPublicKey.get(), commitmentHash.get()});

        // ensure the elgamal public key instance is set as a fixed base
        elGamalPublicKey->setIsFixedBase(true);

        return make_unique<CiphertextElectionContext>(
          numberOfGuardians, quorum, move(elGamalPublicKey), move(commitmentHash),
          move(manifestHash), move(cryptoBaseHash), move(cryptoExtendedBaseHash),
          move(extendedData));
    }

    unique_ptr<CiphertextElectionContext> CiphertextElectionContext::make(
      uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
      unique_ptr<ElementModQ> commitmentHash, unique_ptr<ElementModQ> manifestHash,
      unique_ptr<ContextConfiguration> config,
      std::unordered_map<std::string, std::string> extendedData)
    {
        // TODO: configurable version code

        // HP = H(HV ;00,p,q,g). Parameter Hash 3.1.2
        auto versionCode = string_to_fixed_width_bytes<32>("v2.0");
        auto parameterHash = hash_elems(
          {versionCode, HashPrefix::get_prefix_parameter_hash(), &const_cast<ElementModP &>(P()),
           &const_cast<ElementModQ &>(Q()), &const_cast<ElementModP &>(G())});

        // HM = H(HP;01,manifest). Manifest Hash 3.1.4
        auto manifestDigest = hash_elems(
          {parameterHash.get(), HashPrefix::get_prefix_manifest_hash(), manifestHash.get()});

        // TODO: complete according to spec
        // HB =(HP;02,n,k,date,info,HM). Election Base Hash 3.1.5
        auto cryptoBaseHash = hash_elems({parameterHash.get(), HashPrefix::get_prefix_base_hash(),
                                          manifestDigest.get(), numberOfGuardians, quorum});

        // HE = H(HB;12,K,K1,0,K1,1,...,K1,k−1,K2,0,...,Kn,k−2,Kn,k−1). // Extended Base Hash 3.2.3
        auto cryptoExtendedBaseHash =
          hash_elems({cryptoBaseHash.get(), HashPrefix::get_prefix_extended_hash(),
                      elGamalPublicKey.get(), commitmentHash.get()});

        // ensure the elgamal public key instance is set as a fixed base
        elGamalPublicKey->setIsFixedBase(true);

        return make_unique<CiphertextElectionContext>(
          numberOfGuardians, quorum, move(elGamalPublicKey), move(commitmentHash),
          move(manifestHash), move(cryptoBaseHash), move(cryptoExtendedBaseHash), move(config),
          move(extendedData));
    }

    unique_ptr<CiphertextElectionContext> CiphertextElectionContext::make(
      uint64_t numberOfGuardians, uint64_t quorum, const string &elGamalPublicKeyInHex,
      const string &commitmentHashInHex, const string &manifestHashInHex)
    {
        auto elGamalPublicKey = ElementModP::fromHex(elGamalPublicKeyInHex);
        auto commitmentHash = ElementModQ::fromHex(commitmentHashInHex);
        auto manifestHash = ElementModQ::fromHex(manifestHashInHex);

        // ensure the elgamal public key instance is set as a fixed base
        elGamalPublicKey->setIsFixedBase(true);

        return make(numberOfGuardians, quorum, move(elGamalPublicKey), move(commitmentHash),
                    move(manifestHash));
    }

    unique_ptr<CiphertextElectionContext> CiphertextElectionContext::make(
      uint64_t numberOfGuardians, uint64_t quorum, const string &elGamalPublicKeyInHex,
      const string &commitmentHashInHex, const string &manifestHashInHex,
      std::unordered_map<std::string, std::string> extendedData)
    {
        auto elGamalPublicKey = ElementModP::fromHex(elGamalPublicKeyInHex);
        auto commitmentHash = ElementModQ::fromHex(commitmentHashInHex);
        auto manifestHash = ElementModQ::fromHex(manifestHashInHex);

        // ensure the elgamal public key instance is set as a fixed base
        elGamalPublicKey->setIsFixedBase(true);

        return make(numberOfGuardians, quorum, move(elGamalPublicKey), move(commitmentHash),
                    move(manifestHash), move(extendedData));
    }

    unique_ptr<CiphertextElectionContext> CiphertextElectionContext::make(
      uint64_t numberOfGuardians, uint64_t quorum, const string &elGamalPublicKeyInHex,
      const string &commitmentHashInHex, const string &manifestHashInHex,
      unique_ptr<ContextConfiguration> config)
    {
        auto elGamalPublicKey = ElementModP::fromHex(elGamalPublicKeyInHex);
        auto commitmentHash = ElementModQ::fromHex(commitmentHashInHex);
        auto manifestHash = ElementModQ::fromHex(manifestHashInHex);

        // ensure the elgamal public key instance is set as a fixed base
        elGamalPublicKey->setIsFixedBase(true);

        return make(numberOfGuardians, quorum, move(elGamalPublicKey), move(commitmentHash),
                    move(manifestHash), move(config));
    }

    unique_ptr<CiphertextElectionContext> CiphertextElectionContext::make(
      uint64_t numberOfGuardians, uint64_t quorum, const string &elGamalPublicKeyInHex,
      const string &commitmentHashInHex, const string &manifestHashInHex,
      unique_ptr<ContextConfiguration> config,
      std::unordered_map<std::string, std::string> extendedData)
    {
        auto elGamalPublicKey = ElementModP::fromHex(elGamalPublicKeyInHex);
        auto commitmentHash = ElementModQ::fromHex(commitmentHashInHex);
        auto manifestHash = ElementModQ::fromHex(manifestHashInHex);

        // ensure the elgamal public key instance is set as a fixed base
        elGamalPublicKey->setIsFixedBase(true);

        return make(numberOfGuardians, quorum, move(elGamalPublicKey), move(commitmentHash),
                    move(manifestHash), move(config), move(extendedData));
    }

    // ── v2.1 dual-key make overload ───────────────────────────────────────────

    unique_ptr<CiphertextElectionContext> CiphertextElectionContext::make(
      uint64_t numberOfGuardians, uint64_t quorum, unique_ptr<ElementModP> elGamalPublicKey,
      unique_ptr<ElementModP> ballotDataPublicKey, const vector<uint8_t> &manifestBytes)
    {
        auto parameterHash = computeParameterHash(numberOfGuardians, quorum);
        auto baseHash = computeBaseHash(parameterHash.get(), manifestBytes);
        auto extendedHash =
          computeExtendedHash(baseHash.get(), elGamalPublicKey.get(), ballotDataPublicKey.get());

        elGamalPublicKey->setIsFixedBase(true);

        return make_unique<CiphertextElectionContext>(
          numberOfGuardians, quorum, move(elGamalPublicKey), move(ballotDataPublicKey),
          move(baseHash), move(extendedHash));
    }

    // ── v2.1 hash-chain building blocks ──────────────────────────────────────

    unique_ptr<ElementModQ> CiphertextElectionContext::computeParameterHash(uint64_t n, uint64_t k)
    {
        // H_P = H(version; 0x00, p, q, g, n, k)
        return hash_elems_v21(
          EG_V21_VERSION_BYTES, EG_DS_PARAMETER_HASH,
          {const_cast<ElementModP *>(&P()), const_cast<ElementModQ *>(&Q()),
           const_cast<ElementModP *>(&G()), n, k});
    }

    unique_ptr<ElementModQ>
    CiphertextElectionContext::computeBaseHash(const ElementModQ *parameterHash,
                                               const vector<uint8_t> &manifestBytes)
    {
        // H_B = H(H_P; 0x01, len(manifest), manifest)
        auto manifestLen = static_cast<uint64_t>(manifestBytes.size());
        return hash_elems_v21(parameterHash, EG_DS_ELECTION_BASE_HASH,
                              {manifestLen, manifestBytes});
    }

    unique_ptr<ElementModQ>
    CiphertextElectionContext::computeExtendedHash(const ElementModQ *baseHash,
                                                   const ElementModP *elGamalPublicKey,
                                                   const ElementModP *ballotDataPublicKey)
    {
        // H_E = H(H_B; 0x14, K, K_hat)
        return hash_elems_v21(baseHash, EG_DS_EXTENDED_BASE_HASH,
                              {const_cast<ElementModP *>(elGamalPublicKey),
                               const_cast<ElementModP *>(ballotDataPublicKey)});
    }

#pragma endregion

} // namespace electionguard
