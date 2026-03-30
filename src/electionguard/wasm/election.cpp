#include "electionguard/election.hpp"

#include "../log.hpp"

#include <emscripten/bind.h>
#include <iostream>

using namespace emscripten;
using namespace electionguard;
using namespace std;

/// Helper class that adapts v2.1 static hash-chain builders and dual-key make()
/// for Embind. Embind cannot bind raw-pointer parameters to JS directly, so we
/// accept const references (or strings in place of vector<uint8_t>) and forward.
class ElectionContextV21Functions
{
  public:
    /// Constructs a v2.1 CiphertextElectionContext from the two public keys
    /// and the manifest serialised as a UTF-8 JSON string.
    static std::unique_ptr<CiphertextElectionContext>
    makeV21(uint64_t numberOfGuardians, uint64_t quorum,
            ElementModP &elGamalPublicKey,
            ElementModP &ballotDataPublicKey,
            const std::string &manifestJson)
    {
        std::vector<uint8_t> manifestBytes(manifestJson.begin(), manifestJson.end());
        return CiphertextElectionContext::make(
          numberOfGuardians, quorum,
          elGamalPublicKey.clone(), ballotDataPublicKey.clone(),
          manifestBytes);
    }

    /// v2.1 H_P = H(version; 0x00, p, q, g, n, k)
    static std::unique_ptr<ElementModQ>
    computeParameterHash(uint64_t numberOfGuardians, uint64_t quorum)
    {
        return CiphertextElectionContext::computeParameterHash(numberOfGuardians, quorum);
    }

    /// v2.1 H_B = H(H_P; 0x01, len(manifest), manifest)
    /// manifestJson is treated as raw UTF-8 bytes (JSON string from JS).
    static std::unique_ptr<ElementModQ>
    computeBaseHash(const ElementModQ &parameterHash, const std::string &manifestJson)
    {
        std::vector<uint8_t> manifestBytes(manifestJson.begin(), manifestJson.end());
        return CiphertextElectionContext::computeBaseHash(&parameterHash, manifestBytes);
    }

    /// v2.1 H_E = H(H_B; 0x14, K, K_hat)
    static std::unique_ptr<ElementModQ>
    computeExtendedHash(const ElementModQ &baseHash, const ElementModP &elGamalPublicKey,
                        const ElementModP &ballotDataPublicKey)
    {
        return CiphertextElectionContext::computeExtendedHash(&baseHash, &elGamalPublicKey,
                                                              &ballotDataPublicKey);
    }
};

EMSCRIPTEN_BINDINGS(electionguard)
{
    class_<ContextConfiguration>("ContextConfiguration")
      .constructor()
      .constructor<const bool, const uint64_t>()
      .function("getMaxNumberOfBallots", &ContextConfiguration::getMaxNumberOfBallots)
      .function("getAllowOverVotes", &ContextConfiguration::getAllowOverVotes)
      .class_function("make", &ContextConfiguration::make);

    class_<CiphertextElectionContext>("CiphertextElectionContext")
      .function("getNumberOfGuardians", &CiphertextElectionContext::getNumberOfGuardians)
      .function("getQuorum", &CiphertextElectionContext::getQuorum)
      .function("getElGamalPublicKey", &CiphertextElectionContext::getElGamalPublicKey,
                allow_raw_pointers())
      .function("getElGamalPublicKeyRef", &CiphertextElectionContext::getElGamalPublicKeyRef)
      .function("getManifestHash", &CiphertextElectionContext::getManifestHash,
                allow_raw_pointers())
      .function("getCryptoExtendedBaseHash", &CiphertextElectionContext::getCryptoExtendedBaseHash,
                allow_raw_pointers())
      .function("toJson", &CiphertextElectionContext::toJson)
      .class_function("fromJson", &CiphertextElectionContext::fromJson)
      // v2.1 additions
      .function("getBallotDataPublicKey", &CiphertextElectionContext::getBallotDataPublicKey,
                allow_raw_pointers())
      .function("getCryptoBaseHash", &CiphertextElectionContext::getCryptoBaseHash,
                allow_raw_pointers());

    class_<ElectionContextV21Functions>("ElectionContextV21Functions")
      .class_function("makeV21", &ElectionContextV21Functions::makeV21)
      .class_function("computeParameterHash", &ElectionContextV21Functions::computeParameterHash)
      .class_function("computeBaseHash", &ElectionContextV21Functions::computeBaseHash)
      .class_function("computeExtendedHash", &ElectionContextV21Functions::computeExtendedHash);
}
