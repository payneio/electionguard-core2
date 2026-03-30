#include <doctest/doctest.h>
#include <electionguard/election.hpp>
#include <electionguard/guardian.hpp>
#include <electionguard/group.hpp>

using namespace electionguard;
using namespace std;

TEST_CASE("v2.1 Guardian generates three key pairs (vote, data, communication)")
{
    // Arrange
    const uint64_t guardianIndex = 1;
    const uint64_t quorum = 3;

    // Act
    auto keySet = GuardianKeySet::generate(guardianIndex, quorum);

    // Assert – all three public keys are non-null
    CHECK(keySet != nullptr);
    CHECK(keySet->getVotePublicKey() != nullptr);
    CHECK(keySet->getDataPublicKey() != nullptr);
    CHECK(keySet->getCommPublicKey() != nullptr);

    // Assert – all three public keys are distinct
    CHECK(*keySet->getVotePublicKey() != *keySet->getDataPublicKey());
    CHECK(*keySet->getVotePublicKey() != *keySet->getCommPublicKey());
    CHECK(*keySet->getDataPublicKey() != *keySet->getCommPublicKey());
}

TEST_CASE("v2.1 Guardian generates Feldman commitments for both polynomials")
{
    // Arrange
    const uint64_t guardianIndex = 2;
    const uint64_t quorum = 3;

    // Act
    auto keySet = GuardianKeySet::generate(guardianIndex, quorum);
    auto voteCommitments = keySet->getVoteCommitments();
    auto dataCommitments = keySet->getDataCommitments();

    // Assert – each commitment vector has exactly quorum entries
    CHECK(voteCommitments.size() == quorum);
    CHECK(dataCommitments.size() == quorum);

    // Assert – first commitment matches the guardian's primary public key
    CHECK(*voteCommitments[0] == *keySet->getVotePublicKey());
    CHECK(*dataCommitments[0] == *keySet->getDataPublicKey());
}

TEST_CASE("v2.1 Consolidated Schnorr proof covers all coefficients plus comm key")
{
    // Arrange
    const uint64_t guardianIndex = 1;
    const uint64_t quorum = 3;
    // Use a random element as stand-in for H_P (parameter hash)
    auto parameterHash = rand_q();
    auto keySet = GuardianKeySet::generate(guardianIndex, quorum);

    // Act – generate vote key proof
    auto voteProof = keySet->generateVoteKeyProof(parameterHash.get());

    // Assert – proof exists and has quorum+1 responses
    // (quorum responses for the polynomial coefficients, 1 for the comm key)
    CHECK(voteProof != nullptr);
    CHECK(voteProof->getChallenge() != nullptr);
    CHECK(voteProof->getResponseCount() == quorum + 1);

    // Assert – proof verifies against its own commitments
    auto voteCommitments = keySet->getVoteCommitments();
    CHECK(voteProof->isValid(parameterHash.get(), voteCommitments,
                             keySet->getCommPublicKey(), guardianIndex, "pk_vote"));

    // Act – generate data key proof
    auto dataProof = keySet->generateDataKeyProof(parameterHash.get());

    // Assert – data proof also has quorum+1 responses and verifies
    CHECK(dataProof != nullptr);
    CHECK(dataProof->getResponseCount() == quorum + 1);
    auto dataCommitments = keySet->getDataCommitments();
    CHECK(dataProof->isValid(parameterHash.get(), dataCommitments,
                             keySet->getCommPublicKey(), guardianIndex, "pk_data"));
}

TEST_CASE("v2.1 Share encryption: guardian i encrypts shares for guardian l")
{
    uint64_t quorum = 2;
    auto guardian1 = GuardianKeySet::generate(1, quorum);
    auto guardian2 = GuardianKeySet::generate(2, quorum);

    // Guardian 1 encrypts its share for guardian 2
    auto encrypted = guardian1->encryptShareFor(
        2, guardian2->getCommunicationPublicKey(),
        CiphertextElectionContext::computeParameterHash(3, quorum).get());
    REQUIRE(encrypted != nullptr);

    // Guardian 2 can decrypt the share
    auto decrypted = guardian2->decryptShareFrom(1, *encrypted);
    REQUIRE(decrypted != nullptr);

    // Decrypted share matches direct evaluation
    auto directVoteShare = guardian1->evaluateVotePolynomial(2);
    auto directDataShare = guardian1->evaluateDataPolynomial(2);
    CHECK((*decrypted->getVoteShare() == *directVoteShare));
    CHECK((*decrypted->getDataShare() == *directDataShare));

    // Schnorr proof on the DH pair verifies
    CHECK(encrypted->isProofValid(
        CiphertextElectionContext::computeParameterHash(3, quorum).get(),
        guardian2->getCommunicationPublicKey()));
}

TEST_CASE("v2.1 Joint keys and guardian record hash")
{
    uint64_t n = 3; uint64_t k = 2;
    auto g1 = GuardianKeySet::generate(1, k);
    auto g2 = GuardianKeySet::generate(2, k);
    auto g3 = GuardianKeySet::generate(3, k);

    // Joint vote key: K = product(K_i) mod p
    auto K = GuardianKeySet::computeJointVoteKey({g1.get(), g2.get(), g3.get()});
    REQUIRE(K != nullptr);

    // Joint data key: K_hat = product(K_hat_i) mod p
    auto K_hat = GuardianKeySet::computeJointDataKey({g1.get(), g2.get(), g3.get()});
    REQUIRE(K_hat != nullptr);
    CHECK((*K != *K_hat));

    // H_G = H(H_B; 0x13, K, K_hat, all vote commitments, all data commitments, all comm keys)
    auto hp = CiphertextElectionContext::computeParameterHash(n, k);
    vector<uint8_t> manifest = {0x01};
    auto hb = CiphertextElectionContext::computeBaseHash(hp.get(), manifest);

    auto hg = GuardianKeySet::computeGuardianRecordHash(
        hb.get(), K.get(), K_hat.get(), {g1.get(), g2.get(), g3.get()});
    REQUIRE(hg != nullptr);
}
