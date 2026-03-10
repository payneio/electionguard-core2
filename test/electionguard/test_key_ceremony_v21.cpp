#include <doctest/doctest.h>
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
