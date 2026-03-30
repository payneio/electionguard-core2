/// test_e2e_v21.cpp
///
/// Full v2.1 election lifecycle end-to-end test.
///
/// Exercises the five phases defined in the implementation plan:
///   Phase 1 – Key ceremony (3 guardians, quorum 2)
///   Phase 2 – Election context  (H_B, H_E)
///   Phase 3 – Encrypt 5 ballots with simple chaining
///   Phase 4 – Close the ballot chain
///   Phase 5 – Verify all confirmation codes are unique

#include <doctest/doctest.h>
#include <electionguard/ballot_code.hpp>
#include <electionguard/chaum_pedersen.hpp>
#include <electionguard/election.hpp>
#include <electionguard/elgamal.hpp>
#include <electionguard/group.hpp>
#include <electionguard/guardian.hpp>
#include <electionguard/nonces.hpp>

#include <set>
#include <string>
#include <vector>

using namespace electionguard;
using namespace std;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: homomorphically accumulate nonces mod q
// ─────────────────────────────────────────────────────────────────────────────
static unique_ptr<ElementModQ> accumulate_nonces(const vector<unique_ptr<ElementModQ>> &nonces)
{
    // Start from a copy of the first nonce, then keep adding
    auto acc = nonces[0]->clone();
    for (size_t i = 1; i < nonces.size(); ++i) {
        acc = add_mod_q(*acc, *nonces[i]);
    }
    return acc;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 1 + 2 helper: run the key ceremony and return context artefacts
// ─────────────────────────────────────────────────────────────────────────────
struct CeremonyResult {
    unique_ptr<ElementModP>        K;       // joint vote public key
    unique_ptr<ElementModP>        K_hat;   // joint data public key
    unique_ptr<ElementModQ>        H_P;     // parameter hash
    unique_ptr<ElementModQ>        H_B;     // base hash
    unique_ptr<ElementModQ>        H_E;     // extended hash
    unique_ptr<ElementModQ>        H_G;     // guardian record hash
};

static CeremonyResult run_key_ceremony()
{
    const uint64_t n = 3, k = 2;

    // — Generate guardian key sets ——————————————————————————————————————————
    auto g1 = GuardianKeySet::generate(1, k);
    auto g2 = GuardianKeySet::generate(2, k);
    auto g3 = GuardianKeySet::generate(3, k);

    vector<const GuardianKeySet *> all = {g1.get(), g2.get(), g3.get()};

    // — Compute parameter hash ————————————————————————————————————————————
    auto H_P = CiphertextElectionContext::computeParameterHash(n, k);
    REQUIRE(H_P != nullptr);

    // — Verify consolidated Schnorr proofs for each guardian ——————————————
    // Helper lambda so we can supply the correct guardian index per key set
    auto verifyProofs = [&H_P](GuardianKeySet *gks, uint64_t idx) {
        auto voteProof = gks->generateVoteKeyProof(H_P.get());
        REQUIRE(voteProof != nullptr);
        CHECK(voteProof->isValid(H_P.get(), gks->getVoteCommitments(),
                                 gks->getCommPublicKey(), idx, "pk_vote"));

        auto dataProof = gks->generateDataKeyProof(H_P.get());
        REQUIRE(dataProof != nullptr);
        CHECK(dataProof->isValid(H_P.get(), gks->getDataCommitments(),
                                 gks->getCommPublicKey(), idx, "pk_data"));
    };
    verifyProofs(g1.get(), 1);
    verifyProofs(g2.get(), 2);
    verifyProofs(g3.get(), 3);

    // — Encrypt shares (each guardian encrypts for each other) ————————————
    // g1 → g2, g1 → g3
    auto enc12 = g1->encryptShareFor(2, g2->getCommunicationPublicKey(), H_P.get());
    REQUIRE(enc12 != nullptr);
    CHECK(enc12->isProofValid(H_P.get(), g2->getCommunicationPublicKey()));

    auto enc13 = g1->encryptShareFor(3, g3->getCommunicationPublicKey(), H_P.get());
    REQUIRE(enc13 != nullptr);

    // g2 → g1, g2 → g3
    auto enc21 = g2->encryptShareFor(1, g1->getCommunicationPublicKey(), H_P.get());
    REQUIRE(enc21 != nullptr);
    auto enc23 = g2->encryptShareFor(3, g3->getCommunicationPublicKey(), H_P.get());
    REQUIRE(enc23 != nullptr);

    // g3 → g1, g3 → g2
    auto enc31 = g3->encryptShareFor(1, g1->getCommunicationPublicKey(), H_P.get());
    REQUIRE(enc31 != nullptr);
    auto enc32 = g3->encryptShareFor(2, g2->getCommunicationPublicKey(), H_P.get());
    REQUIRE(enc32 != nullptr);

    // — Compute joint keys ————————————————————————————————————————————————
    auto K     = GuardianKeySet::computeJointVoteKey(all);
    auto K_hat = GuardianKeySet::computeJointDataKey(all);
    REQUIRE(K != nullptr);
    REQUIRE(K_hat != nullptr);
    CHECK(*K != *K_hat);

    // — Compute H_B and H_E ———————————————————————————————————————————————
    vector<uint8_t> manifestBytes = {0x01, 0x02, 0x03};  // minimal stub manifest
    auto H_B = CiphertextElectionContext::computeBaseHash(H_P.get(), manifestBytes);
    REQUIRE(H_B != nullptr);

    auto H_E = CiphertextElectionContext::computeExtendedHash(H_B.get(), K.get(), K_hat.get());
    REQUIRE(H_E != nullptr);

    // — Compute guardian record hash H_G ——————————————————————————————————
    auto H_G = GuardianKeySet::computeGuardianRecordHash(H_B.get(), K.get(), K_hat.get(), all);
    REQUIRE(H_G != nullptr);

    return {move(K), move(K_hat), move(H_P), move(H_B), move(H_E), move(H_G)};
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST CASE: v2.1 E2E: Full election lifecycle
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("v2.1 E2E: Full election lifecycle – key ceremony to chain close")
{
    // ── Phase 1+2: Key ceremony and election context ────────────────────────
    auto ceremony = run_key_ceremony();
    auto &K     = *ceremony.K;
    auto &K_hat = *ceremony.K_hat;
    auto &H_E   = *ceremony.H_E;

    // ── Phase 3: Set up chaining for 5 ballots ──────────────────────────────
    const string deviceInfo = "Precinct 1, Scanner 2";
    auto H_DI    = BallotCode::computeDeviceInfoHash(&H_E, deviceInfo);
    REQUIRE(H_DI != nullptr);

    // simple-chain init: B_{C,0} = 0x00000001 || H_DI
    auto initField = BallotCode::buildSimpleChainInitField(H_DI.get());
    REQUIRE(initField.size() == 36);

    // chain seed: H_0 = H(H_E; 0x29, B_{C,0})
    auto H_0 = BallotCode::computeChainInitHash(&H_E, initField);
    REQUIRE(H_0 != nullptr);

    // ── Phase 3: Encrypt 5 ballots ──────────────────────────────────────────
    //
    // Contest layout: 1 contest, 2 selections, max votes = 1
    // Ballot pattern: odd-indexed ballots vote selection-0; even-indexed vote selection-1
    //
    const uint64_t NUM_BALLOTS    = 5;
    const uint64_t CONTEST_IDX    = 0;
    const uint64_t NUM_SELECTIONS = 2;
    const uint64_t MAX_VOTES      = 1;

    vector<unique_ptr<ElementModQ>> confirmationCodes;
    unique_ptr<ElementModQ>         H_prev = H_0->clone();   // chaining state

    for (uint64_t b = 0; b < NUM_BALLOTS; ++b) {

        // ── Ballot identity and nonce ────────────────────────────────────────
        auto id_B  = rand_q();   // random ballot identifier
        auto xi_B  = rand_q();   // ballot nonce

        // H_I = H(H_E; 0x20, id_B)
        auto H_I = compute_selection_encryption_id(&H_E, id_B.get());
        REQUIRE(H_I != nullptr);

        // Encrypt the ballot nonce with K_hat so auditors can challenge
        auto encNonce = HashedElGamalCiphertext::encryptBallotNonce(
            xi_B.get(), &K_hat, H_I.get());
        REQUIRE(encNonce != nullptr);
        CHECK(encNonce->isNonceProofValid(&K_hat, H_I.get()));

        // ── Encrypt selections ───────────────────────────────────────────────
        // Alternate vote pattern
        uint64_t votes[NUM_SELECTIONS] = {
            (b % 2 == 0) ? 1U : 0U,   // selection 0
            (b % 2 == 0) ? 0U : 1U    // selection 1
        };

        vector<unique_ptr<ElementModQ>>      selNonces;
        vector<unique_ptr<ElGamalCiphertext>> selCts;

        for (uint64_t s = 0; s < NUM_SELECTIONS; ++s) {
            // per-selection nonce: xi_{i,j} = H_q(H_I; 0x21, i, j, xi_B)
            auto xi_sel = derive_selection_nonce(H_I.get(), CONTEST_IDX, s, xi_B.get());
            REQUIRE(xi_sel != nullptr);

            // encrypt: (alpha, beta) = (g^xi, K^xi * g^m)
            auto ct = elgamalEncrypt(votes[s], *xi_sel, K);
            REQUIRE(ct != nullptr);

            // selection range proof (proves value is 0 or 1)
            auto proof = UnifiedRangeProof::make(
                *ct, *xi_sel, votes[s], MAX_VOTES,
                K, *H_I, CONTEST_IDX, s);
            REQUIRE(proof != nullptr);
            CHECK(proof->isValid(*ct, K, *H_I, CONTEST_IDX, s));

            selNonces.push_back(move(xi_sel));
            selCts.push_back(move(ct));
        }

        // ── Contest limit proof ──────────────────────────────────────────────
        // Accumulate all selections homomorphically
        auto accCt = selCts[0]->elgamalAdd(*selCts[1]);
        REQUIRE(accCt != nullptr);

        // Accumulate nonces: sum(xi_sel_j) mod q
        auto accR = accumulate_nonces(selNonces);

        // Contest limit = MAX_VOTES; total selected = 1 always in this scheme
        uint64_t totalVotes = votes[0] + votes[1];  // always 1
        auto contestLimitProof = UnifiedRangeProof::makeContestLimit(
            *accCt, *accR, totalVotes, MAX_VOTES,
            K, *H_I, CONTEST_IDX);
        REQUIRE(contestLimitProof != nullptr);
        CHECK(contestLimitProof->isValidContestLimit(*accCt, K, *H_I, CONTEST_IDX));

        // ── Contest hash ─────────────────────────────────────────────────────
        // chi_l = H(H_I; 0x28, l, alpha_1, beta_1, ..., alpha_n, beta_n)
        vector<const ElGamalCiphertext *> ctPtrs;
        for (auto &c : selCts) {
            ctPtrs.push_back(c.get());
        }
        auto chi = BallotCode::computeContestHash(H_I.get(), CONTEST_IDX, ctPtrs, nullptr);
        REQUIRE(chi != nullptr);

        // ── Chaining field for this ballot ────────────────────────────────────
        // B_{C,b} = 0x00000001 || H_{b-1}  (b=0 uses H_0 wrapped in initField already)
        vector<uint8_t> chainingField =
            (b == 0) ? initField : BallotCode::buildSimpleChainField(H_prev.get());

        // ── Confirmation code ─────────────────────────────────────────────────
        // H_C = H(H_I; 0x29, chi_1, ..., chi_m, B_C)
        vector<const ElementModQ *> contestHashes = {chi.get()};
        auto H_C = BallotCode::computeConfirmationCode(H_I.get(), contestHashes, chainingField);
        REQUIRE(H_C != nullptr);

        confirmationCodes.push_back(H_C->clone());
        H_prev = move(H_C);
    }

    CHECK(confirmationCodes.size() == NUM_BALLOTS);

    // ── Phase 4: Close the chain ─────────────────────────────────────────────
    auto H_bar = BallotCode::closeChain(&H_E, H_prev.get(), initField);
    REQUIRE(H_bar != nullptr);

    // Closing hash is reproducible
    auto H_bar2 = BallotCode::closeChain(&H_E, H_prev.get(), initField);
    CHECK(*H_bar == *H_bar2);

    // ── Phase 5: All confirmation codes are unique ────────────────────────────
    set<string> seen;
    for (const auto &hc : confirmationCodes) {
        auto hex = hc->toHex();
        CHECK(seen.find(hex) == seen.end());
        seen.insert(hex);
    }
    CHECK(seen.size() == NUM_BALLOTS);
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST CASE: v2.1 E2E: Key ceremony proofs validate
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("v2.1 E2E: Key ceremony – Schnorr proofs and share encryption validate")
{
    const uint64_t n = 3, k = 2;
    auto H_P = CiphertextElectionContext::computeParameterHash(n, k);
    REQUIRE(H_P != nullptr);

    auto g1 = GuardianKeySet::generate(1, k);
    auto g2 = GuardianKeySet::generate(2, k);
    auto g3 = GuardianKeySet::generate(3, k);

    // Each guardian's vote + data proofs must verify
    struct GuardianEntry {
        GuardianKeySet *gks;
        uint64_t        idx;
    };
    vector<GuardianEntry> entries = {{g1.get(), 1}, {g2.get(), 2}, {g3.get(), 3}};

    for (auto &e : entries) {
        auto vp = e.gks->generateVoteKeyProof(H_P.get());
        REQUIRE(vp != nullptr);
        auto voteComms = e.gks->getVoteCommitments();
        CHECK(vp->isValid(H_P.get(), voteComms, e.gks->getCommPublicKey(),
                          e.idx, "pk_vote"));

        auto dp = e.gks->generateDataKeyProof(H_P.get());
        REQUIRE(dp != nullptr);
        auto dataComms = e.gks->getDataCommitments();
        CHECK(dp->isValid(H_P.get(), dataComms, e.gks->getCommPublicKey(),
                          e.idx, "pk_data"));
    }

    // Share encryption round-trip: g1 → g2
    auto enc12 = g1->encryptShareFor(2, g2->getCommunicationPublicKey(), H_P.get());
    REQUIRE(enc12 != nullptr);
    CHECK(enc12->isProofValid(H_P.get(), g2->getCommunicationPublicKey()));

    auto dec12 = g2->decryptShareFrom(1, *enc12);
    REQUIRE(dec12 != nullptr);
    CHECK(*dec12->getVoteShare() == *g1->evaluateVotePolynomial(2));
    CHECK(*dec12->getDataShare() == *g1->evaluateDataPolynomial(2));
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST CASE: v2.1 E2E: Election context hash chain
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("v2.1 E2E: Election context – H_P → H_B → H_E hash chain is deterministic")
{
    const uint64_t n = 3, k = 2;

    auto g1 = GuardianKeySet::generate(1, k);
    auto g2 = GuardianKeySet::generate(2, k);
    auto g3 = GuardianKeySet::generate(3, k);
    vector<const GuardianKeySet *> all = {g1.get(), g2.get(), g3.get()};

    auto K     = GuardianKeySet::computeJointVoteKey(all);
    auto K_hat = GuardianKeySet::computeJointDataKey(all);

    vector<uint8_t> manifestBytes = {0xAB, 0xCD};

    auto H_P  = CiphertextElectionContext::computeParameterHash(n, k);
    auto H_B  = CiphertextElectionContext::computeBaseHash(H_P.get(), manifestBytes);
    auto H_E  = CiphertextElectionContext::computeExtendedHash(H_B.get(), K.get(), K_hat.get());

    // Recompute to confirm determinism
    auto H_P2 = CiphertextElectionContext::computeParameterHash(n, k);
    CHECK(*H_P == *H_P2);

    auto H_E2 = CiphertextElectionContext::computeExtendedHash(H_B.get(), K.get(), K_hat.get());
    CHECK(*H_E == *H_E2);

    // Different manifest → different H_B
    vector<uint8_t> other = {0xFF};
    auto H_B_other = CiphertextElectionContext::computeBaseHash(H_P.get(), other);
    CHECK(*H_B != *H_B_other);
}
