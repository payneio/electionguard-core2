#include "../../src/electionguard/log.hpp"
#include "generators/election.hpp"
#include "generators/manifest.hpp"

#include <doctest/doctest.h>
#include <electionguard/constants.h>
#include <electionguard/election.hpp>
#include <electionguard/elgamal.hpp>
#include <electionguard/group.hpp>
#include <electionguard/manifest.hpp>
#include <unordered_map>
#include <vector>

using namespace electionguard;
using namespace electionguard::tools::generators;
using namespace std;

TEST_CASE("Can serialize CiphertextElectionContext")
{
    // Arrange
    auto keypair = ElGamalKeyPair::fromSecret(TWO_MOD_Q());
    auto manifest = ManifestGenerator::getJeffersonCountyManifest_Minimal();
    auto internal = make_unique<InternalManifest>(*manifest);
    auto context = ElectionGenerator::getFakeContext(*internal, *keypair->getPublicKey());
    auto json = context->toJson();
    auto bson = context->toBson();

    Log::debug(json);

    // Act
    auto fromJson = CiphertextElectionContext::fromJson(json);
    auto fromBson = CiphertextElectionContext::fromBson(bson);

    // Assert
    // validate against manifest->getManifestHash()
    CHECK(fromJson->getManifestHash()->toHex() == context->getManifestHash()->toHex());
    CHECK(fromBson->getManifestHash()->toHex() == context->getManifestHash()->toHex());
}

TEST_CASE("Assign ExtraData to CiphertextElectionContext")
{
    // Arrange
    auto key = "ballot_base_uri";
    auto value = "http://something.vote/";
    unordered_map<string, string> extendedData({{key, value}});

    // Act
    auto context = CiphertextElectionContext::make(
      3UL, 2UL, TWO_MOD_P().clone(), TWO_MOD_Q().clone(), TWO_MOD_Q().clone(), extendedData);

    auto cached = context->getExtendedData();
    auto resolved = cached.find(key);

    // Assert
    if (resolved == cached.end()) {
        FAIL(resolved);
    } else {
        CHECK(resolved->second == value);
    }
}

TEST_CASE("Assign ExtraData to CiphertextElectionContextand Serialize")
{
    // Arrange
    auto key = "uri";
    auto value = "http://something.vote/";
    unordered_map<string, string> extendedData({{key, value}});

    // Act
    auto context = CiphertextElectionContext::make(
      3UL, 2UL, TWO_MOD_P().clone(), TWO_MOD_Q().clone(), TWO_MOD_Q().clone(), extendedData);

    auto json = context->toJson();
    auto bson = context->toBson();

    Log::debug(json);

    // Act
    auto fromJson = CiphertextElectionContext::fromJson(json);
    auto fromBson = CiphertextElectionContext::fromBson(bson);

    // Assert
    CHECK(fromJson->getExtendedData().at("uri") == context->getExtendedData().at("uri"));
    CHECK(fromBson->getExtendedData().at("uri") == context->getExtendedData().at("uri"));
}

// ─── v2.1 generator tests ────────────────────────────────────────────────────

TEST_CASE("v2.1 ElectionGenerator::getFakeContextV21 creates dual-key context")
{
    // Arrange
    auto elGamalKeypair     = ElGamalKeyPair::fromSecret(TWO_MOD_Q());
    auto ballotDataSecret   = rand_q();
    auto ballotDataKeypair  = ElGamalKeyPair::fromSecret(*ballotDataSecret);
    auto manifest           = ManifestGenerator::getJeffersonCountyManifest_Minimal();
    auto internal           = make_unique<InternalManifest>(*manifest);

    // Act
    auto context = ElectionGenerator::getFakeContextV21(
      *internal, *elGamalKeypair->getPublicKey(), *ballotDataKeypair->getPublicKey());

    // Assert
    REQUIRE(context != nullptr);
    CHECK(context->getNumberOfGuardians() == 3UL);
    CHECK(context->getQuorum() == 2UL);
    CHECK(context->getElGamalPublicKey() != nullptr);
    CHECK(context->getBallotDataPublicKey() != nullptr);
    CHECK(context->getCryptoBaseHash() != nullptr);
    CHECK(context->getCryptoExtendedBaseHash() != nullptr);
}

// ─── v2.1 base hash chain tests ─────────────────────────────────────────────

TEST_CASE("v2.1 H_P includes n and k, uses version bytes as key")
{
    // computeParameterHash should return non-null
    auto hp1 = CiphertextElectionContext::computeParameterHash(3UL, 2UL);
    REQUIRE(hp1 != nullptr);

    // Same (n, k) → same H_P (deterministic)
    auto hp2 = CiphertextElectionContext::computeParameterHash(3UL, 2UL);
    REQUIRE(hp2 != nullptr);
    CHECK((*hp1 == *hp2));

    // Different n → different H_P (n is included in the hash)
    auto hp3 = CiphertextElectionContext::computeParameterHash(5UL, 2UL);
    REQUIRE(hp3 != nullptr);
    CHECK((*hp1 != *hp3));
}

TEST_CASE("v2.1 H_B eliminates H_M, uses raw manifest directly")
{
    auto hp = CiphertextElectionContext::computeParameterHash(3UL, 2UL);
    REQUIRE(hp != nullptr);

    vector<uint8_t> manifestBytes1 = {0x01, 0x02, 0x03, 0x04};
    vector<uint8_t> manifestBytes2 = {0x05, 0x06, 0x07, 0x08};

    // computeBaseHash should return non-null
    auto hb1 = CiphertextElectionContext::computeBaseHash(hp.get(), manifestBytes1);
    REQUIRE(hb1 != nullptr);

    // Different manifest bytes → different H_B
    auto hb2 = CiphertextElectionContext::computeBaseHash(hp.get(), manifestBytes2);
    REQUIRE(hb2 != nullptr);
    CHECK((*hb1 != *hb2));
}

TEST_CASE("v2.1 H_E includes K_hat")
{
    auto hp = CiphertextElectionContext::computeParameterHash(3UL, 2UL);
    REQUIRE(hp != nullptr);

    vector<uint8_t> manifestBytes = {0x01, 0x02, 0x03};
    auto hb = CiphertextElectionContext::computeBaseHash(hp.get(), manifestBytes);
    REQUIRE(hb != nullptr);

    // Use two distinct public key values
    auto K     = TWO_MOD_P().clone();
    auto Khat1 = G().clone();
    auto Khat2 = P().clone();

    // computeExtendedHash should return non-null
    auto he1 = CiphertextElectionContext::computeExtendedHash(hb.get(), K.get(), Khat1.get());
    REQUIRE(he1 != nullptr);

    // Changing K_hat → different H_E
    auto he2 = CiphertextElectionContext::computeExtendedHash(hb.get(), K.get(), Khat2.get());
    REQUIRE(he2 != nullptr);
    CHECK((*he1 != *he2));
}

TEST_CASE("v2.1 CiphertextElectionContext::make uses HMAC-based hash chain")
{
    vector<uint8_t> manifestBytes = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto K    = TWO_MOD_P().clone();
    auto Khat = G().clone();

    auto context =
      CiphertextElectionContext::make(3UL, 2UL, move(K), move(Khat), manifestBytes);
    REQUIRE(context != nullptr);

    // Core fields populated
    CHECK(context->getNumberOfGuardians() == 3UL);
    CHECK(context->getQuorum() == 2UL);
    CHECK(context->getElGamalPublicKey() != nullptr);
    CHECK(context->getBallotDataPublicKey() != nullptr);
    CHECK(context->getCryptoBaseHash() != nullptr);
    CHECK(context->getCryptoExtendedBaseHash() != nullptr);
}
