#include <doctest/doctest.h>
#include <electionguard/decryption.hpp>
#include <electionguard/elgamal.hpp>
#include <electionguard/group.hpp>
#include <electionguard/hash.hpp>
#include <electionguard/nonces.hpp>

using namespace electionguard;
using namespace std;

TEST_CASE("v2.1 weighted homomorphic tally: product(alpha_j^W_j, beta_j^W_j)")
{
    auto keypair = ElGamalKeyPair::fromSecret(TWO_MOD_Q());
    auto nonce1 = rand_q();
    auto nonce2 = rand_q();

    // Two ballots: selection=1, selection=0, weights=2 and 3
    auto ct1 = elgamalEncrypt(1UL, *nonce1, *keypair->getPublicKey());
    auto ct2 = elgamalEncrypt(0UL, *nonce2, *keypair->getPublicKey());

    vector<const ElGamalCiphertext *> ciphertexts = {ct1.get(), ct2.get()};
    vector<uint64_t> weights = {2, 3};

    auto tally = ElGamalCiphertext::weightedAccumulate(ciphertexts, weights);
    REQUIRE(tally != nullptr);

    // Tally pad and data should be non-trivial
    CHECK(tally->getPad() != nullptr);
    CHECK(tally->getData() != nullptr);
}

TEST_CASE("v2.1 weighted tally: equal weights reduce to homomorphic sum")
{
    auto keypair = ElGamalKeyPair::fromSecret(TWO_MOD_Q());
    auto nonce1 = rand_q();
    auto nonce2 = rand_q();

    auto ct1 = elgamalEncrypt(1UL, *nonce1, *keypair->getPublicKey());
    auto ct2 = elgamalEncrypt(1UL, *nonce2, *keypair->getPublicKey());

    // Weight=1 for both should equal homomorphic add
    vector<const ElGamalCiphertext *> ciphertexts = {ct1.get(), ct2.get()};
    vector<uint64_t> weights = {1, 1};

    auto weighted = ElGamalCiphertext::weightedAccumulate(ciphertexts, weights);
    auto added = ct1->elgamalAdd(*ct2);

    CHECK((*weighted->getPad() == *added->getPad()));
    CHECK((*weighted->getData() == *added->getData()));
}

TEST_CASE("v2.1 commit-to-commitment: hash is deterministic")
{
    auto H_E = rand_q();
    auto A = g_pow_p(ONE_MOD_Q());
    auto B = g_pow_p(ONE_MOD_Q());
    auto u = rand_q();
    auto a_i = g_pow_p(*u);
    auto b_i = pow_mod_p(*A, *u);
    auto M_i = g_pow_p(ONE_MOD_Q());

    vector<uint64_t> available = {1, 2, 3};

    auto d1 = DecryptionProof::computeCommitmentHash(
        H_E.get(), 0, 0, 1,
        A.get(), B.get(), a_i.get(), b_i.get(), M_i.get(), available);
    auto d2 = DecryptionProof::computeCommitmentHash(
        H_E.get(), 0, 0, 1,
        A.get(), B.get(), a_i.get(), b_i.get(), M_i.get(), available);

    REQUIRE(d1 != nullptr);
    CHECK((*d1 == *d2));

    // Different guardian index produces different hash
    auto d3 = DecryptionProof::computeCommitmentHash(
        H_E.get(), 0, 0, 2,
        A.get(), B.get(), a_i.get(), b_i.get(), M_i.get(), available);
    CHECK((*d1 != *d3));
}

TEST_CASE("v2.1 decryption proof: full round-trip with single guardian")
{
    auto H_E = rand_q();
    auto keypair = ElGamalKeyPair::fromSecret(TWO_MOD_Q());
    auto nonce = rand_q();

    // Encrypt selection = 1
    auto ct = elgamalEncrypt(1UL, *nonce, *keypair->getPublicKey());

    // Partial decryption: M = A^s mod p
    auto M = pow_mod_p(*ct->getPad(), *keypair->getSecretKey());

    // Proof commitment: random u, a = g^u, b = A^u
    auto u = rand_q();
    auto a = g_pow_p(*u);
    auto b = pow_mod_p(*ct->getPad(), *u);

    // Challenge
    auto challenge = DecryptionProof::computeDecryptionChallenge(
        H_E.get(), 0, 0,
        ct->getPad(), ct->getData(),
        a.get(), b.get(), M.get());
    REQUIRE(challenge != nullptr);

    // Response: v = u - c * s mod q
    auto cs = mul_mod_q(*challenge, *keypair->getSecretKey());
    auto v = sub_mod_q(*u, *cs);

    // Construct proof and verify
    auto proof = make_unique<DecryptionProof>(
        a->clone(), b->clone(), challenge->clone(), v->clone());

    CHECK(proof->isValid(*ct, *keypair->getPublicKey(), *M, *H_E, 0, 0));
}

TEST_CASE("v2.1 challenged ballot: decrypt nonce, re-derive nonces, verify")
{
    auto keypair = ElGamalKeyPair::fromSecret(TWO_MOD_Q());
    auto kHatPair = ElGamalKeyPair::fromSecret(*rand_q());
    auto H_E = rand_q();
    auto id_B = rand_q();
    auto xi_B = rand_q(); // ballot nonce

    auto H_I = compute_selection_encryption_id(H_E.get(), id_B.get());

    // Encrypt ballot nonce with K_hat
    auto nonceCt = HashedElGamalCiphertext::encryptBallotNonce(
        xi_B.get(), kHatPair->getPublicKey(), H_I.get());

    // Encrypt a selection with derived nonce
    uint64_t contestIdx = 0, selIdx = 0;
    auto derived_nonce = derive_selection_nonce(H_I.get(), contestIdx, selIdx, xi_B.get());
    auto ct = elgamalEncrypt(1UL, *derived_nonce, *keypair->getPublicKey());

    // Guardians decrypt the ballot nonce
    auto decrypted_xi_B = nonceCt->decryptBallotNonce(
        kHatPair->getSecretKey(), H_I.get());
    REQUIRE((*decrypted_xi_B == *xi_B));

    // Verifier re-derives nonces and checks ciphertext
    auto re_derived = derive_selection_nonce(H_I.get(), contestIdx, selIdx, decrypted_xi_B.get());
    auto re_ct = elgamalEncrypt(1UL, *re_derived, *keypair->getPublicKey());
    CHECK((*re_ct->getPad() == *ct->getPad()));
    CHECK((*re_ct->getData() == *ct->getData()));
}

TEST_CASE("v2.1 contest data commitment hash: d_i = H(H_I; 0x32, ...)")
{
    auto H_I = rand_q();
    auto keypair = ElGamalKeyPair::fromSecret(TWO_MOD_Q());
    auto xi_B = rand_q();
    uint64_t contestIndex = 0;

    // Encrypt contest data
    vector<uint8_t> contestData(32, 0xCD);
    auto encrypted = HashedElGamalCiphertext::encryptContestData(
        contestData, keypair->getPublicKey(), H_I.get(), contestIndex, xi_B.get());

    // Commitment
    auto u = rand_q();
    auto a_i = g_pow_p(*u);
    auto b_i = pow_mod_p(*encrypted->getPad(), *u);
    auto m_i = pow_mod_p(*encrypted->getPad(), *keypair->getSecretKey());

    auto d_i = DecryptionProof::computeContestDataCommitmentHash(
        H_I.get(), contestIndex, 1,
        encrypted->getPad(), encrypted->getData(), encrypted->getMac(),
        a_i.get(), b_i.get(), m_i.get(), {1});
    REQUIRE(d_i != nullptr);

    // Deterministic
    auto d_i_2 = DecryptionProof::computeContestDataCommitmentHash(
        H_I.get(), contestIndex, 1,
        encrypted->getPad(), encrypted->getData(), encrypted->getMac(),
        a_i.get(), b_i.get(), m_i.get(), {1});
    CHECK((*d_i == *d_i_2));
}

TEST_CASE("v2.1 contest data decryption challenge: c = H_q(H_I; 0x33, ...)")
{
    auto H_I = rand_q();
    auto keypair = ElGamalKeyPair::fromSecret(TWO_MOD_Q());
    auto xi_B = rand_q();
    uint64_t contestIndex = 0;

    vector<uint8_t> contestData(32, 0xCD);
    auto encrypted = HashedElGamalCiphertext::encryptContestData(
        contestData, keypair->getPublicKey(), H_I.get(), contestIndex, xi_B.get());

    auto u = rand_q();
    auto a = g_pow_p(*u);
    auto b = pow_mod_p(*encrypted->getPad(), *u);
    auto M = pow_mod_p(*encrypted->getPad(), *keypair->getSecretKey());

    auto challenge = DecryptionProof::computeContestDataDecryptionChallenge(
        H_I.get(), contestIndex,
        encrypted->getPad(), encrypted->getData(), encrypted->getMac(),
        a.get(), b.get(), M.get());
    REQUIRE(challenge != nullptr);

    // Deterministic
    auto challenge2 = DecryptionProof::computeContestDataDecryptionChallenge(
        H_I.get(), contestIndex,
        encrypted->getPad(), encrypted->getData(), encrypted->getMac(),
        a.get(), b.get(), M.get());
    CHECK((*challenge == *challenge2));
}
