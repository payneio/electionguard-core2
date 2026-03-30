#include <doctest/doctest.h>
#include <electionguard/ballot_code.hpp>
#include <electionguard/elgamal.hpp>
#include <electionguard/group.hpp>
#include <electionguard/hash.hpp>
#include <electionguard/log.hpp>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

using namespace electionguard;
using namespace std;

TEST_CASE("Get rotating ballot code rotates")
{
    // Arrange
    auto deviceHash =
      BallotCode::getHashForDevice(12345UL, 23456UL, 34567UL, "some-location-string");
    uint64_t firstHash[MAX_Q_LEN] = {1};
    auto firstBallotHash = make_unique<ElementModQ>(firstHash);
    uint64_t secondHash[MAX_Q_LEN] = {2};
    auto secondBallotHash = make_unique<ElementModQ>(secondHash);

    // Act
    auto rotatingHash1 = BallotCode::getBallotCode(*deviceHash, 1000UL, *firstBallotHash);
    auto rotatingHash2 = BallotCode::getBallotCode(*rotatingHash1, 1001UL, *secondBallotHash);

    //Assert
    CHECK(deviceHash != nullptr);
    CHECK(rotatingHash1 != nullptr);
    CHECK(rotatingHash2 != nullptr);

    CHECK(rotatingHash1 != deviceHash);
    CHECK(rotatingHash2 != deviceHash);
    CHECK(rotatingHash1 != rotatingHash2);

    CHECK((*rotatingHash1 != *deviceHash));
    CHECK(&rotatingHash1 != &deviceHash);

    CHECK((*rotatingHash2 != *deviceHash));
    CHECK(&rotatingHash2 != &deviceHash);

    CHECK((*rotatingHash1 != *rotatingHash2));
    CHECK(&rotatingHash1 != &rotatingHash2);
}

TEST_CASE("v2.1 contest hash: chi_l = H(H_I; 0x28, l, alpha_1, beta_1, ...)")
{
    auto H_I = rand_q();
    uint64_t contestIndex = 0;
    auto keypair = ElGamalKeyPair::fromSecret(TWO_MOD_Q());

    // Create two encrypted selections
    auto nonce1 = rand_q();
    auto nonce2 = rand_q();
    auto ct1 = elgamalEncrypt(1UL, *nonce1, *keypair->getPublicKey());
    auto ct2 = elgamalEncrypt(0UL, *nonce2, *keypair->getPublicKey());

    vector<const ElGamalCiphertext *> selections = {ct1.get(), ct2.get()};

    auto chi = BallotCode::computeContestHash(H_I.get(), contestIndex, selections, nullptr);
    REQUIRE(chi != nullptr);

    // Deterministic
    auto chi2 = BallotCode::computeContestHash(H_I.get(), contestIndex, selections, nullptr);
    CHECK((*chi == *chi2));

    // Different contest index produces different hash
    auto chi3 = BallotCode::computeContestHash(H_I.get(), 1, selections, nullptr);
    CHECK((*chi != *chi3));
}

TEST_CASE("v2.1 device info hash: H_DI = H(H_E; 0x2A, S_device)")
{
    auto H_E = rand_q();
    string deviceInfo = "Precinct 42, Scanner A";

    auto H_DI = BallotCode::computeDeviceInfoHash(H_E.get(), deviceInfo);
    REQUIRE(H_DI != nullptr);

    // Deterministic
    auto H_DI_again = BallotCode::computeDeviceInfoHash(H_E.get(), deviceInfo);
    CHECK((*H_DI == *H_DI_again));

    // Different device info produces different hash
    auto H_DI_2 = BallotCode::computeDeviceInfoHash(H_E.get(), "Other device");
    CHECK((*H_DI != *H_DI_2));
}

TEST_CASE("v2.1 confirmation code: H_C = H(H_I; 0x29, chi_1, ..., chi_m, B_C)")
{
    auto H_I = rand_q();
    auto chi_1 = rand_q();
    auto chi_2 = rand_q();
    vector<const ElementModQ *> contestHashes = {chi_1.get(), chi_2.get()};

    // No-chaining field: 4 zero bytes mode + 32 bytes hash
    vector<uint8_t> chainingField(36, 0x00);

    auto H_C = BallotCode::computeConfirmationCode(H_I.get(), contestHashes, chainingField);
    REQUIRE(H_C != nullptr);

    // Deterministic
    auto H_C_again = BallotCode::computeConfirmationCode(H_I.get(), contestHashes, chainingField);
    CHECK((*H_C == *H_C_again));

    // Different chaining field produces different hash
    vector<uint8_t> differentChain(36, 0x01);
    auto H_C_2 = BallotCode::computeConfirmationCode(H_I.get(), contestHashes, differentChain);
    CHECK((*H_C != *H_C_2));
}
