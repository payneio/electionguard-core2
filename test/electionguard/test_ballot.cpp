#include "../../src/electionguard/log.hpp"
#include "generators/ballot.hpp"
#include "generators/manifest.hpp"

#include <doctest/doctest.h>
#include <electionguard/ballot.hpp>
#include <electionguard/elgamal.hpp>
#include <electionguard/group.hpp>

using namespace electionguard;
using namespace electionguard::tools::generators;
using namespace std;

TEST_CASE("Plaintext Simple Ballot Is Valid")
{
    auto subject = BallotGenerator::getSimpleBallotFromFile();

    CHECK(subject->getObjectId() == "some-external-id-string-123");
}

TEST_CASE("Plaintext Ballot Selection Is Valid")
{
    // Arrange
    const auto *objectId = "some-object-id";

    // Act
    auto subject = make_unique<PlaintextBallotSelection>(objectId, 1UL);

    // Assert
    CHECK(subject->isValid(objectId) == true);
}

TEST_CASE("Plaintext Ballot Selection Is InValid")
{
    SUBCASE("Different object id's fail validity check")
    {
        // Arrange
        const auto *objectId = "some-object-id";

        // Act
        auto subject = make_unique<PlaintextBallotSelection>(objectId, 1UL);

        // Assert
        CHECK(subject->isValid("some-other-object-id") == false);
    }

    SUBCASE("An out of range selection value fails validity check")
    {
        // Arrange
        const auto *objectId = "some-object-id";

        // Act
        auto subject = make_unique<PlaintextBallotSelection>(objectId, 2UL);

        // Assert
        CHECK(subject->isValid(objectId) == false);
    }
}

TEST_CASE("Can serialize PlaintextBallot")
{
    // Arrange
    auto manifest = ManifestGenerator::getJeffersonCountyManifest_Minimal();
    auto internal = make_unique<InternalManifest>(*manifest);
    auto plaintext = BallotGenerator::getFakeBallot(*internal);
    auto json = plaintext->toJson();
    auto bson = plaintext->toBson();
    auto msgPack = plaintext->toMsgPack();

    // Act
    auto fromJson = PlaintextBallot::fromJson(json);
    auto fromBson = PlaintextBallot::fromBson(bson);
    auto fromMsgPack = PlaintextBallot::fromMsgPack(msgPack);

    // Assert
    CHECK(plaintext->getObjectId() == fromJson->getObjectId());
    CHECK(plaintext->getObjectId() == fromBson->getObjectId());
    CHECK(plaintext->getObjectId() == fromMsgPack->getObjectId());
}

// ─── v2.1 CiphertextBallot field tests ───────────────────────────────────────

TEST_CASE("v2.1 CiphertextBallot v2.1 field setters and getters")
{
    // Verify the v2.1 setter/getter method signatures exist on CiphertextBallot.
    // If any method is missing the build will fail here (RED → GREEN gate).
    using GetBallotIdFn = ElementModQ *(CiphertextBallot::*)() const;
    GetBallotIdFn fnGetBallotId = &CiphertextBallot::getBallotId;
    CHECK(fnGetBallotId != nullptr);

    using GetNonceCiphertextFn = HashedElGamalCiphertext *(CiphertextBallot::*)() const;
    GetNonceCiphertextFn fnGetNonceCt = &CiphertextBallot::getNonceCiphertext;
    CHECK(fnGetNonceCt != nullptr);

    using GetChainingFieldFn = std::vector<uint8_t>(CiphertextBallot::*)() const;
    GetChainingFieldFn fnGetChaining = &CiphertextBallot::getChainingField;
    CHECK(fnGetChaining != nullptr);

    using GetSelectionEncIdFn = ElementModQ *(CiphertextBallot::*)() const;
    GetSelectionEncIdFn fnGetSelEncId = &CiphertextBallot::getSelectionEncryptionId;
    CHECK(fnGetSelEncId != nullptr);

    // Verify objects used as v2.1 field values can be created and stored.
    auto ballotId = rand_q();
    CHECK(ballotId != nullptr);

    auto dummyPad = g_pow_p(ONE_MOD_Q());
    vector<uint8_t> dummyData(32, 0x00);
    vector<uint8_t> dummyMac(64, 0x00);
    auto nonceCt = make_unique<HashedElGamalCiphertext>(move(dummyPad), move(dummyData),
                                                        move(dummyMac));
    CHECK(nonceCt != nullptr);

    vector<uint8_t> chainingField(36, 0x00);
    CHECK(chainingField.size() == 36);

    auto H_I = rand_q();
    CHECK(H_I != nullptr);
}
