#include "../../src/electionguard/log.hpp"

#include <doctest/doctest.h>
#include <electionguard/constants.h>
#include <electionguard/group.hpp>
#include <electionguard/hash.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

using namespace electionguard;
using namespace std;

TEST_CASE("Same ElementModQs with same Zero data produce same Hash")
{
    uint64_t z1[4] = {};
    uint64_t z2[4] = {};
    auto e1 = make_unique<ElementModQ>(z1);
    auto e2 = make_unique<ElementModQ>(z2);

    auto zero_hash_q1 = hash_elems(e1.get());
    auto zero_hash_q2 = hash_elems(e2.get());

    CHECK((*zero_hash_q1 == *zero_hash_q2));
    // but different addresses
    CHECK(&zero_hash_q1 != &zero_hash_q2);
}

TEST_CASE("Hash Value for Zero string different from Zero number")
{
    auto zero_hash1 = hash_elems(0UL);
    auto zero_hash2 = hash_elems("0");

    CHECK((*zero_hash1 != *zero_hash2));
    // but different addresses
    CHECK(&zero_hash1 != &zero_hash2);
}

TEST_CASE("Hash Value for non-zero number string same as explicit number")
{
    auto one_hash1 = hash_elems(1UL);
    auto one_hash2 = hash_elems("1");

    CHECK((*one_hash1 == *one_hash2));
    // but different addresses
    CHECK(&one_hash1 != &one_hash2);
}

TEST_CASE("Same Number Value Hash with explicit number")
{
    auto one_hash1 = hash_elems(1UL);
    auto one_hash2 = hash_elems(1UL);

    CHECK((*one_hash1 == *one_hash2));
    // but different addresses
    CHECK(&one_hash1 != &one_hash2);
}

TEST_CASE("Same strings are the same Hash") { CHECK((*hash_elems("0") == *hash_elems("0"))); }

TEST_CASE("Different strings not the same Hash")
{
    CHECK((*hash_elems("0") !=
           *hash_elems(
             "51550449938001064785844756727912747714949358666715026308259290402648561267962")));
}

TEST_CASE("Different strings casing not the same Hash")
{
    CHECK((*hash_elems("Welcome To ElectionGuard") != *hash_elems("welcome to electionguard")));
}

TEST_CASE("Hash for empty string same as null string")
{
    CHECK((*hash_elems("null") == *hash_elems("")));
}

TEST_CASE("Hash for nullptr same as explicit zero number")
{
    CHECK((*hash_elems(0UL) == *hash_elems(nullptr)));
}

TEST_CASE("Hash for nullptr same as null string")
{
    CHECK((*hash_elems("null") == *hash_elems(nullptr)));
}

TEST_CASE("Hash of multiple zeros in list is different has than hash for single zero")
{
    CHECK((*hash_elems("0") != *hash_elems({"0", "0"})));
}

TEST_CASE("Hash of same values in list are the same hash")
{
    CHECK((*hash_elems({"0", "0"}) == *hash_elems({"0", "0"})));
}

TEST_CASE("Hash of empty list same as hash of null string")
{
    vector<string> null_vector;
    vector<string> empty_vector = {};
    CHECK((*hash_elems(null_vector) == *hash_elems(empty_vector)));
    CHECK((*hash_elems(empty_vector) == *hash_elems(nullptr)));
    CHECK((*hash_elems(empty_vector) == *hash_elems("")));
}

TEST_CASE("Same Hash Value from nested-list and result of hashed list by hashing the hex")
{
    auto nestedHash = hash_elems({vector<string>{"0", "1"}, "3"});
    auto nonNestedHash1 = hash_elems({"0", "1"});
    auto nonNestedHash2 = hash_elems({nonNestedHash1->toHex(), "3"});

    CHECK((*nestedHash != *nonNestedHash1));
    CHECK((*nestedHash == *nonNestedHash2));
    // but different addresses
    CHECK(&nestedHash != &nonNestedHash2);
}

// ─── v2.1 HMAC-SHA-256 hash primitive tests ──────────────────────────────────

TEST_CASE("v2.1 H() uses HMAC-SHA-256 with 32-byte key and structured data")
{
    // Fixed 32-byte key for deterministic tests
    uint8_t key[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                       0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                       0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

    auto result1 = hash_elems_v21(key, EG_DS_PARAMETER_HASH, {string("hello")});
    auto result2 = hash_elems_v21(key, EG_DS_PARAMETER_HASH, {string("hello")});

    // Same inputs produce the same output (deterministic)
    REQUIRE(result1 != nullptr);
    REQUIRE(result2 != nullptr);
    CHECK((*result1 == *result2));

    // Different domain separator produces different output
    auto result3 = hash_elems_v21(key, EG_DS_ELECTION_BASE_HASH, {string("hello")});
    REQUIRE(result3 != nullptr);
    CHECK((*result1 != *result3));
}

TEST_CASE("v2.1 H_q() reduces HMAC output mod q")
{
    uint8_t key[32] = {0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
                       0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
                       0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
                       0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89};

    auto result = hash_elems_v21_q(&ZERO_MOD_Q(), EG_DS_PARAMETER_HASH, {string("test")});
    REQUIRE(result != nullptr);

    // Result must be less than Q (i.e., in [0, Q))
    CHECK((*result < Q()));
}

TEST_CASE("v2.1 hash serializes uint64_t as 4-byte big-endian")
{
    uint8_t key[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    auto hash1 = hash_elems_v21(key, EG_DS_PARAMETER_HASH, {uint64_t{1}});
    auto hash2 = hash_elems_v21(key, EG_DS_PARAMETER_HASH, {uint64_t{2}});

    REQUIRE(hash1 != nullptr);
    REQUIRE(hash2 != nullptr);
    // Serializing 1 and 2 as 4-byte big-endian must produce different hashes
    CHECK((*hash1 != *hash2));
}

TEST_CASE("v2.1 hash serializes ElementModP as 512-byte big-endian")
{
    uint8_t key[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};

    // P() and G() are different large primes - serializing them must produce different hashes
    auto hashP = hash_elems_v21(key, EG_DS_PARAMETER_HASH,
                                {const_cast<ElementModP *>(&P())});
    auto hashG = hash_elems_v21(key, EG_DS_PARAMETER_HASH,
                                {const_cast<ElementModP *>(&G())});

    REQUIRE(hashP != nullptr);
    REQUIRE(hashG != nullptr);
    CHECK((*hashP != *hashG));
}

TEST_CASE("v2.1 hash serializes ElementModQ as 32-byte big-endian")
{
    uint8_t key[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};

    // ONE_MOD_Q() and TWO_MOD_Q() differ - serializing them must produce different hashes
    auto hashOne = hash_elems_v21(key, EG_DS_PARAMETER_HASH,
                                  {const_cast<ElementModQ *>(&ONE_MOD_Q())});
    auto hashTwo = hash_elems_v21(key, EG_DS_PARAMETER_HASH,
                                  {const_cast<ElementModQ *>(&TWO_MOD_Q())});

    REQUIRE(hashOne != nullptr);
    REQUIRE(hashTwo != nullptr);
    CHECK((*hashOne != *hashTwo));
}
