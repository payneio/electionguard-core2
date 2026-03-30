#include <doctest/doctest.h>
#include <electionguard/group.hpp>
#include <electionguard/hash.hpp>
#include <electionguard/nonces.hpp>
#include <iostream>

using namespace electionguard;
using namespace std;

TEST_CASE("Nonces with same seed generated same output")
{
    uint64_t a[4] = {};
    auto aModQ = make_unique<ElementModQ>(a);
    auto n1 = make_unique<Nonces>(*aModQ);
    auto n2 = make_unique<Nonces>(*aModQ);

    CHECK(n1->get(0)->toHex() == n2->get(0)->toHex());
}

TEST_CASE("Nonce seeded with header is different from Nonce seeded without header")
{
    uint64_t a[4] = {};
    auto aModQ = make_unique<ElementModQ>(a);
    auto n1 = make_unique<Nonces>(*aModQ);
    auto n2 = make_unique<Nonces>(*aModQ, "0");

    CHECK(n1->get(0)->toHex() != n2->get(0)->toHex());
}

TEST_CASE("Nonces slices produce same output as iterating for each index")
{
    uint64_t a[4] = {};
    auto aModQ = make_unique<ElementModQ>(a);
    auto n = make_unique<Nonces>(*aModQ);
    vector<unique_ptr<ElementModQ>> l1;
    l1.reserve(10);
    for (uint64_t i(0); i < 10; ++i) {
        l1.push_back(n->get(i));
    }
    auto n2 = make_unique<Nonces>(*aModQ);
    auto l2 = n2->get(0UL, 10UL);

    CHECK(l1.size() == l2.size());

    for (size_t i(0); i < l1.size(); ++i) {
        CHECK(l1[i]->toHex() == l2[i]->toHex());
    }
}

// ─── v2.1 H_I and nonce derivation ───────────────────────────────────────────

TEST_CASE("v2.1 H_I: selection encryption identifier is deterministic")
{
    auto H_E = rand_q();
    auto id_B = rand_q();

    auto H_I_1 = compute_selection_encryption_id(H_E.get(), id_B.get());
    auto H_I_2 = compute_selection_encryption_id(H_E.get(), id_B.get());

    REQUIRE(H_I_1 != nullptr);
    REQUIRE(H_I_2 != nullptr);
    CHECK((*H_I_1 == *H_I_2));
}

TEST_CASE("v2.1 H_I: different ballot IDs produce different H_I values")
{
    auto H_E = rand_q();
    auto id_B_1 = rand_q();
    auto id_B_2 = rand_q();

    auto H_I_1 = compute_selection_encryption_id(H_E.get(), id_B_1.get());
    auto H_I_2 = compute_selection_encryption_id(H_E.get(), id_B_2.get());

    CHECK((*H_I_1 != *H_I_2));
}

TEST_CASE("v2.1 nonce derivation: distinct nonces per (contest, selection)")
{
    auto H_I = rand_q();
    auto xi_B = rand_q();

    auto n_0_0 = derive_selection_nonce(H_I.get(), 0, 0, xi_B.get());
    auto n_0_1 = derive_selection_nonce(H_I.get(), 0, 1, xi_B.get());
    auto n_1_0 = derive_selection_nonce(H_I.get(), 1, 0, xi_B.get());

    REQUIRE(n_0_0 != nullptr);
    REQUIRE(n_0_1 != nullptr);
    REQUIRE(n_1_0 != nullptr);

    // All three nonces are distinct
    CHECK((*n_0_0 != *n_0_1));
    CHECK((*n_0_0 != *n_1_0));
    CHECK((*n_0_1 != *n_1_0));
}

TEST_CASE("v2.1 contest data nonce: distinct from selection nonces")
{
    auto H_I = rand_q();
    auto xi_B = rand_q();

    auto sel_nonce = derive_selection_nonce(H_I.get(), 0, 0, xi_B.get());
    auto data_nonce = derive_contest_data_nonce(H_I.get(), 0, xi_B.get());

    REQUIRE(sel_nonce != nullptr);
    REQUIRE(data_nonce != nullptr);

    // Different domain separators produce different values
    CHECK((*sel_nonce != *data_nonce));
}
