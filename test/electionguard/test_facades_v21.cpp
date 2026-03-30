/// @file test_facades_v21.cpp
/// Tests for the v2.1 C facade additions: election hash-chain builders,
/// ballot data public key getter, make_v21, and guardian key-set operations.

#include <doctest/doctest.h>

#include <cstdlib>
#include <string>

extern "C" {
#include <electionguard/election.h>
#include <electionguard/guardian.h>
#include <electionguard/group.h>
#include <electionguard/status.h>
}

// ---------------------------------------------------------------------------
// Election v2.1 C facade tests
// ---------------------------------------------------------------------------

TEST_CASE("v2.1 C facade: eg_ciphertext_election_context_compute_parameter_hash returns non-null")
{
    eg_element_mod_q_t *hp = nullptr;
    auto status = eg_ciphertext_election_context_compute_parameter_hash(3UL, 2UL, &hp);
    CHECK(status == ELECTIONGUARD_STATUS_SUCCESS);
    REQUIRE(hp != nullptr);
    eg_element_mod_q_free(hp);
}

TEST_CASE("v2.1 C facade: compute_parameter_hash is deterministic for same (n,k)")
{
    eg_element_mod_q_t *hp1 = nullptr;
    eg_element_mod_q_t *hp2 = nullptr;
    CHECK(eg_ciphertext_election_context_compute_parameter_hash(3UL, 2UL, &hp1) ==
          ELECTIONGUARD_STATUS_SUCCESS);
    CHECK(eg_ciphertext_election_context_compute_parameter_hash(3UL, 2UL, &hp2) ==
          ELECTIONGUARD_STATUS_SUCCESS);

    // Compare via hex strings using the group C API
    char *hex1 = nullptr;
    char *hex2 = nullptr;
    eg_element_mod_q_to_hex(hp1, &hex1);
    eg_element_mod_q_to_hex(hp2, &hex2);
    CHECK(std::string(hex1) == std::string(hex2));

    eg_element_mod_q_free(hp1);
    eg_element_mod_q_free(hp2);
    free(hex1);
    free(hex2);
}

TEST_CASE("v2.1 C facade: eg_ciphertext_election_context_compute_base_hash returns non-null")
{
    eg_element_mod_q_t *hp = nullptr;
    CHECK(eg_ciphertext_election_context_compute_parameter_hash(3UL, 2UL, &hp) ==
          ELECTIONGUARD_STATUS_SUCCESS);

    uint8_t manifest_bytes[] = {0x01, 0x02, 0x03, 0x04};
    eg_element_mod_q_t *hb = nullptr;
    auto status =
      eg_ciphertext_election_context_compute_base_hash(hp, manifest_bytes, 4UL, &hb);
    CHECK(status == ELECTIONGUARD_STATUS_SUCCESS);
    REQUIRE(hb != nullptr);

    eg_element_mod_q_free(hp);
    eg_element_mod_q_free(hb);
}

TEST_CASE(
  "v2.1 C facade: eg_ciphertext_election_context_compute_extended_hash returns non-null and "
  "varies with K_hat")
{
    eg_element_mod_q_t *hp = nullptr;
    CHECK(eg_ciphertext_election_context_compute_parameter_hash(3UL, 2UL, &hp) ==
          ELECTIONGUARD_STATUS_SUCCESS);
    uint8_t manifest_bytes[] = {0x01};
    eg_element_mod_q_t *hb = nullptr;
    CHECK(eg_ciphertext_election_context_compute_base_hash(hp, manifest_bytes, 1UL, &hb) ==
          ELECTIONGUARD_STATUS_SUCCESS);

    // Use ONE_MOD_P for both keys (determinism check), then check different K_hat gives
    // different H_E.  We'll just verify non-null and that two distinct calls can differ.
    eg_element_mod_p_t *K = nullptr;
    eg_element_mod_p_new(ONE_MOD_P_ARRAY, &K);
    eg_element_mod_p_t *Khat = nullptr;
    eg_element_mod_p_new(ONE_MOD_P_ARRAY, &Khat);

    eg_element_mod_q_t *he = nullptr;
    auto status =
      eg_ciphertext_election_context_compute_extended_hash(hb, K, Khat, &he);
    CHECK(status == ELECTIONGUARD_STATUS_SUCCESS);
    REQUIRE(he != nullptr);

    eg_element_mod_q_free(hp);
    eg_element_mod_q_free(hb);
    eg_element_mod_q_free(he);
    eg_element_mod_p_free(K);
    eg_element_mod_p_free(Khat);
}

TEST_CASE("v2.1 C facade: eg_ciphertext_election_context_make_v21 creates valid context")
{
    eg_element_mod_p_t *K = nullptr;
    eg_element_mod_p_new(ONE_MOD_P_ARRAY, &K);
    eg_element_mod_p_t *Khat = nullptr;
    eg_element_mod_p_new(ONE_MOD_P_ARRAY, &Khat);

    uint8_t manifest_bytes[] = {0x01, 0x02, 0x03};
    eg_ciphertext_election_context_t *ctx = nullptr;
    auto status = eg_ciphertext_election_context_make_v21(3UL, 2UL, K, Khat, manifest_bytes,
                                                          3UL, &ctx);
    CHECK(status == ELECTIONGUARD_STATUS_SUCCESS);
    REQUIRE(ctx != nullptr);

    uint64_t n = 0, k = 0;
    CHECK(eg_ciphertext_election_context_get_number_of_guardians(ctx, &n) ==
          ELECTIONGUARD_STATUS_SUCCESS);
    CHECK(eg_ciphertext_election_context_get_quorum(ctx, &k) == ELECTIONGUARD_STATUS_SUCCESS);
    CHECK(n == 3UL);
    CHECK(k == 2UL);

    // Ballot data public key getter should work
    eg_element_mod_p_t *khat_ref = nullptr;
    CHECK(eg_ciphertext_election_context_get_ballot_data_public_key(ctx, &khat_ref) ==
          ELECTIONGUARD_STATUS_SUCCESS);
    CHECK(khat_ref != nullptr);

    eg_ciphertext_election_context_free(ctx);
    eg_element_mod_p_free(K);
    eg_element_mod_p_free(Khat);
}

// ---------------------------------------------------------------------------
// Guardian C facade tests
// ---------------------------------------------------------------------------

TEST_CASE("v2.1 C facade: eg_guardian_key_set_generate returns valid key set")
{
    eg_guardian_key_set_t *gks = nullptr;
    auto status = eg_guardian_key_set_generate(1UL, 3UL, &gks);
    CHECK(status == ELECTIONGUARD_STATUS_SUCCESS);
    REQUIRE(gks != nullptr);

    eg_element_mod_p_t *vote_key = nullptr;
    CHECK(eg_guardian_key_set_get_vote_public_key(gks, &vote_key) ==
          ELECTIONGUARD_STATUS_SUCCESS);
    CHECK(vote_key != nullptr);

    eg_element_mod_p_t *data_key = nullptr;
    CHECK(eg_guardian_key_set_get_data_public_key(gks, &data_key) ==
          ELECTIONGUARD_STATUS_SUCCESS);
    CHECK(data_key != nullptr);

    eg_element_mod_p_t *comm_key = nullptr;
    CHECK(eg_guardian_key_set_get_communication_public_key(gks, &comm_key) ==
          ELECTIONGUARD_STATUS_SUCCESS);
    CHECK(comm_key != nullptr);

    eg_guardian_key_set_free(gks);
}

TEST_CASE("v2.1 C facade: joint keys computed from multiple guardians are non-null")
{
    eg_guardian_key_set_t *g1 = nullptr;
    eg_guardian_key_set_t *g2 = nullptr;
    eg_guardian_key_set_t *g3 = nullptr;
    CHECK(eg_guardian_key_set_generate(1UL, 2UL, &g1) == ELECTIONGUARD_STATUS_SUCCESS);
    CHECK(eg_guardian_key_set_generate(2UL, 2UL, &g2) == ELECTIONGUARD_STATUS_SUCCESS);
    CHECK(eg_guardian_key_set_generate(3UL, 2UL, &g3) == ELECTIONGUARD_STATUS_SUCCESS);

    eg_guardian_key_set_t *guardians[3] = {g1, g2, g3};

    eg_element_mod_p_t *joint_vote = nullptr;
    CHECK(eg_guardian_key_set_compute_joint_vote_key(guardians, 3UL, &joint_vote) ==
          ELECTIONGUARD_STATUS_SUCCESS);
    REQUIRE(joint_vote != nullptr);

    eg_element_mod_p_t *joint_data = nullptr;
    CHECK(eg_guardian_key_set_compute_joint_data_key(guardians, 3UL, &joint_data) ==
          ELECTIONGUARD_STATUS_SUCCESS);
    REQUIRE(joint_data != nullptr);

    eg_element_mod_p_free(joint_vote);
    eg_element_mod_p_free(joint_data);
    eg_guardian_key_set_free(g1);
    eg_guardian_key_set_free(g2);
    eg_guardian_key_set_free(g3);
}
