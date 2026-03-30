#include "electionguard/elgamal.hpp"

#include "../../libs/hacl/Lib.hpp"
#include "electionguard/constants.h"
#include "electionguard/discrete_log.hpp"
#include "electionguard/hash.hpp"
#include "electionguard/hmac.hpp"
#include "electionguard/kdf.hpp"
#include "electionguard/precompute_buffers.hpp"
#include "facades/bignum4096.hpp"
#include "krml/lowstar_endianness.h"
#include "log.hpp"

#include <array>
#include <electionguard/hash.hpp>
#include <memory>
#include <stdexcept>
#include <string>

using electionguard::HMAC;
using electionguard::facades::Bignum4096;
using std::invalid_argument;
using std::make_unique;
using std::move;
using std::reference_wrapper;
using std::runtime_error;
using std::unique_ptr;

namespace electionguard
{
#pragma region ElgamalKeyPair

    struct ElGamalKeyPair::Impl {
        Impl(unique_ptr<ElementModQ> secretKey, unique_ptr<ElementModP> publicKey)
            : secretKey(move(secretKey)), publicKey(move(publicKey))
        {
        }

        unique_ptr<ElementModQ> secretKey;
        unique_ptr<ElementModP> publicKey;
    };

    // Lifecycle Methods

    ElGamalKeyPair::ElGamalKeyPair(const ElGamalKeyPair &other)
        : pimpl(new Impl(move(*other.pimpl)))
    {
    }

    ElGamalKeyPair::ElGamalKeyPair(unique_ptr<ElementModQ> secretKey,
                                   unique_ptr<ElementModP> publicKey)
        : pimpl(new Impl(move(secretKey), move(publicKey)))
    {
    }

    ElGamalKeyPair &ElGamalKeyPair::operator=(ElGamalKeyPair rhs)
    {
        swap(pimpl, rhs.pimpl);
        return *this;
    }

    ElGamalKeyPair::~ElGamalKeyPair() = default;

    // Property Getters

    ElementModQ *ElGamalKeyPair::getSecretKey() { return pimpl->secretKey.get(); }

    ElementModQ *ElGamalKeyPair::getSecretKey() const { return pimpl->secretKey.get(); }

    ElementModP *ElGamalKeyPair::getPublicKey() { return pimpl->publicKey.get(); }

    ElementModP *ElGamalKeyPair::getPublicKey() const { return pimpl->publicKey.get(); }

    // Public Members

    unique_ptr<ElGamalKeyPair> ElGamalKeyPair::fromSecret(const ElementModQ &secretKey,
                                                          bool isFixedBase /* = true */)
    {
        if (const_cast<ElementModQ &>(secretKey) < TWO_MOD_Q()) {
            throw invalid_argument("ElGamalKeyPair fromSecret secret key needs to be in [2,Q).");
        }
        auto privateKey = make_unique<ElementModQ>(secretKey);
        auto publicKey = g_pow_p(secretKey);
        publicKey->setIsFixedBase(isFixedBase);
        return make_unique<ElGamalKeyPair>(move(privateKey), move(publicKey));
    }

    // TODO: do we really need this??
    unique_ptr<ElGamalKeyPair> ElGamalKeyPair::fromPair(const ElementModQ &secretKey,
                                                        const ElementModP &publicKeyData)
    {
        if (const_cast<ElementModQ &>(secretKey) < TWO_MOD_Q()) {
            throw invalid_argument("ElGamalKeyPair fromSecret secret key needs to be in [2,Q).");
        }
        auto privateKey = make_unique<ElementModQ>(secretKey);
        auto publicKey = make_unique<ElementModP>(publicKeyData);
        return make_unique<ElGamalKeyPair>(move(privateKey), move(publicKey));
    }

#pragma endregion

#pragma region ElGamalCiphertext

    struct ElGamalCiphertext::Impl {
        unique_ptr<ElementModP> pad;
        unique_ptr<ElementModP> data;

        Impl(unique_ptr<ElementModP> pad, unique_ptr<ElementModP> data)
            : pad(move(pad)), data(move(data))
        {
        }

        [[nodiscard]] unique_ptr<ElGamalCiphertext::Impl> clone() const
        {
            auto _pad = make_unique<ElementModP>(*pad);
            auto _data = make_unique<ElementModP>(*data);
            return make_unique<ElGamalCiphertext::Impl>(move(_pad), move(_data));
        }

        [[nodiscard]] unique_ptr<ElementModQ> crypto_hash() const
        {
            return hash_elems({pad.get(), data.get()});
        }

        bool operator==(const Impl &other) { return *pad == *other.pad && *data == *other.data; }
    };

    // Lifecycle Methods

    ElGamalCiphertext::ElGamalCiphertext(const ElGamalCiphertext &other)
        : pimpl(other.pimpl->clone())
    {
    }

    ElGamalCiphertext::ElGamalCiphertext(unique_ptr<ElementModP> pad, unique_ptr<ElementModP> data)
        : pimpl(new Impl(move(pad), move(data)))
    {
    }

    ElGamalCiphertext::~ElGamalCiphertext() = default;

    // Operator Overloads

    ElGamalCiphertext &ElGamalCiphertext::operator=(ElGamalCiphertext rhs)
    {
        swap(pimpl, rhs.pimpl);
        return *this;
    }

    bool ElGamalCiphertext::operator==(const ElGamalCiphertext &other)
    {
        return *pimpl == *other.pimpl;
    }

    bool ElGamalCiphertext::operator!=(const ElGamalCiphertext &other) { return !(*this == other); }

    // Property Getters

    ElementModP *ElGamalCiphertext::getPad() { return pimpl->pad.get(); }
    ElementModP *ElGamalCiphertext::getPad() const { return pimpl->pad.get(); }
    ElementModP *ElGamalCiphertext::getData() { return pimpl->data.get(); }
    ElementModP *ElGamalCiphertext::getData() const { return pimpl->data.get(); }

    // Interface Overrides

    unique_ptr<ElementModQ> ElGamalCiphertext::crypto_hash() { return pimpl->crypto_hash(); }
    unique_ptr<ElementModQ> ElGamalCiphertext::crypto_hash() const { return pimpl->crypto_hash(); }

    unique_ptr<ElGamalCiphertext> ElGamalCiphertext::make(const ElementModP &pad,
                                                          const ElementModP &data)
    {
        return make_unique<ElGamalCiphertext>(make_unique<ElementModP>(pad),
                                              make_unique<ElementModP>(data));
    }

    // Public Methods

    std::unique_ptr<ElGamalCiphertext> ElGamalCiphertext::elgamalAdd(const ElGamalCiphertext &b)
    {
        auto pad = mul_mod_p(*pimpl->pad, *b.pimpl->pad);
        auto data = mul_mod_p(*pimpl->data, *b.pimpl->data);
        return make_unique<ElGamalCiphertext>(move(pad), move(data));
    }

    std::unique_ptr<ElGamalCiphertext> ElGamalCiphertext::elgamalAdd(
      const std::vector<std::reference_wrapper<ElGamalCiphertext>> &ciphertexts)
    {
        auto resultPad = make_unique<ElementModP>(*pimpl->pad);
        auto resultData = make_unique<ElementModP>(*pimpl->data);
        for (auto &ciphertext : ciphertexts) {
            auto pad = mul_mod_p(*resultPad, *ciphertext.get().pimpl->pad);
            resultPad.swap(pad);
            auto data = mul_mod_p(*resultData, *ciphertext.get().pimpl->data);
            resultData.swap(data);
        }
        return make_unique<ElGamalCiphertext>(move(resultPad), move(resultData));
    }

    uint64_t ElGamalCiphertext::decrypt(const ElementModP &shareAccumulation,
                                        const ElementModP &base)
    {
        // T = B · M^−1 mod p
        auto result = div_mod_p(*pimpl->data, shareAccumulation);
        return DiscreteLog::getAsync(*result, base);
    }

    uint64_t ElGamalCiphertext::decrypt(const ElementModP &shareAccumulation,
                                        const ElementModP &base) const
    {
        // T = B · M^−1 mod p
        auto result = div_mod_p(*pimpl->data, shareAccumulation);
        return DiscreteLog::getAsync(*result, base);
    }

    uint64_t ElGamalCiphertext::decrypt(const ElementModQ &secretKey, const ElementModP &base)
    {
        auto difference = sub_from_q(secretKey);
        auto product = pow_mod_p(*pimpl->pad, *difference);
        return decryptKnownProduct(*product, base);
    }

    uint64_t ElGamalCiphertext::decrypt(const ElementModQ &secretKey, const ElementModP &base) const
    {
        auto difference = sub_from_q(secretKey);
        auto product = pow_mod_p(*pimpl->pad, *difference);
        return decryptKnownProduct(*product, base);
    }

    uint64_t ElGamalCiphertext::decrypt(const ElementModP &publicKey, const ElementModQ &nonce)
    {
        auto difference = sub_from_q(nonce);
        auto product = pow_mod_p(publicKey, *difference);
        return decryptKnownProduct(*product, publicKey);
    }

    uint64_t ElGamalCiphertext::decrypt(const ElementModP &publicKey,
                                        const ElementModQ &nonce) const
    {
        auto difference = sub_from_q(nonce);
        auto product = pow_mod_p(publicKey, *difference);
        return decryptKnownProduct(*product, publicKey);
    }

    uint64_t ElGamalCiphertext::decrypt(const ElementModP &publicKey, const ElementModQ &nonce,
                                        const ElementModP &base)
    {
        // E.G. 2.0 Base-K Decrypt
        if (publicKey == base) {
            return decrypt(publicKey, nonce);
        }

        // E.G. 1.0 Compatible Decrypt
        auto product = pow_mod_p(publicKey, nonce);
        auto result = div_mod_p(*pimpl->data, *product);
        return DiscreteLog::getAsync(*result, base);
    }

    uint64_t ElGamalCiphertext::decrypt(const ElementModP &publicKey, const ElementModQ &nonce,
                                        const ElementModP &base) const
    {
        // E.G. 2.0 Base-K Decrypt
        if (publicKey == base) {
            return decrypt(publicKey, nonce);
        }

        // E.G. 1.0 Compatible Decrypt
        auto product = pow_mod_p(publicKey, nonce);
        auto result = div_mod_p(*pimpl->data, *product);
        return DiscreteLog::getAsync(*result, base);
    }

    unique_ptr<ElementModP> ElGamalCiphertext::partialDecrypt(const ElementModQ &secretKey)
    {
        return pow_mod_p(*pimpl->pad, secretKey);
    }

    unique_ptr<ElementModP> ElGamalCiphertext::partialDecrypt(const ElementModQ &secretKey) const
    {
        return pow_mod_p(*pimpl->pad, secretKey);
    }

    unique_ptr<ElGamalCiphertext> ElGamalCiphertext::clone() const
    {
        return make_unique<ElGamalCiphertext>(pimpl->pad->clone(), pimpl->data->clone());
    }

    uint64_t ElGamalCiphertext::decryptKnownProduct(const ElementModP &product,
                                                    const ElementModP &base)
    {
        auto result = mul_mod_p(*pimpl->data, product);
        return DiscreteLog::getAsync(*result, base);
    }

    uint64_t ElGamalCiphertext::decryptKnownProduct(const ElementModP &product,
                                                    const ElementModP &base) const
    {
        auto result = mul_mod_p(*pimpl->data, product);
        return DiscreteLog::getAsync(*result, base);
    }

    unique_ptr<ElGamalCiphertext>
    ElGamalCiphertext::weightedAccumulate(const vector<const ElGamalCiphertext *> &ciphertexts,
                                          const vector<uint64_t> &weights)
    {
        if (ciphertexts.size() != weights.size() || ciphertexts.empty()) {
            throw invalid_argument("ciphertexts and weights must be non-empty and same size");
        }

        // Start with identity: (1, 1)
        auto A = ONE_MOD_P().clone();
        auto B = ONE_MOD_P().clone();

        for (size_t i = 0; i < ciphertexts.size(); ++i) {
            auto w = ElementModQ::fromUint64(weights[i], true);
            auto alpha_w = pow_mod_p(*ciphertexts[i]->getPad(), *w);
            auto beta_w = pow_mod_p(*ciphertexts[i]->getData(), *w);
            A = mul_mod_p(*A, *alpha_w);
            B = mul_mod_p(*B, *beta_w);
        }

        return make_unique<ElGamalCiphertext>(move(A), move(B));
    }

#pragma endregion

    /// <summary>
    /// elgamal encrypt using the provided pad and blinding factor against a specific base
    /// this method supports the case where the encryption base is different than the public key
    /// which was the case in EG 1.0.
    ///
    /// this method is used both for encrypting against G for 1.0 elections
    /// and for encrypting against K for 2.0 elections using precomputed values.
    ///
    /// ecryptionBase (B) is usually either the generator (G()) or the public key of the election (K)
    /// <param name="m">the message to encrypt (m or V in the spec)</param>
    /// <param name="pad">the pad to use for the encryption (g^R mod p)</param>
    /// <param name="blindingFactor">the blinding factor to use for the encryption (K^R mod p)</param>
    /// <param name="publicKey">the public key to use for the encryption (K in the spec)</param>
    /// <param name="encryptionBase">the base to use for the encryption (g or K in the spec)</param>
    /// </summary>
    unique_ptr<ElGamalCiphertext> elgamalEncrypt(uint64_t m, unique_ptr<ElementModP> pad,
                                                 const ElementModP blindingFactor,
                                                 const ElementModP &publicKey,
                                                 const ElementModP &encryptionBase)
    {
        // E.G. 1.0 Compatible ElGamal Encrypt.
        // (g^R mod p, B^V ·K^R mod p)

        unique_ptr<ElementModP> data = nullptr;
        if (m == 1) {
            data = mul_mod_p(encryptionBase, blindingFactor); // B^1 * K^R mod p
        } else if (m == 0) {
            data = blindingFactor.clone(); // B^0 * K^R mod p
        } else {
            auto message = pow_mod_p(encryptionBase, m);
            data = mul_mod_p(*message, blindingFactor); // B^V * K^R mod p
        }

        Log::trace("Compatible Base Generated Encryption");
        Log::trace("publicKey", publicKey.toHex());
        Log::trace("pad", pad->toHex());
        Log::trace("data", data->toHex());

        return make_unique<ElGamalCiphertext>(move(pad), move(data));
    }

    unique_ptr<ElGamalCiphertext> elgamalEncrypt(uint64_t m, const ElementModQ &nonce,
                                                 const ElementModP &publicKey)
    {
        if ((const_cast<ElementModQ &>(nonce) == ZERO_MOD_Q())) {
            throw invalid_argument("elgamalEncrypt encryption requires a non-zero nonce");
        }

        // E.G. 2.0 Base-K ElGamal Encrypt in realtime.
        // (g^R mod p, K^V ·K^R mod p) = (g^R mod p, K^(V+R) mod p)

        auto pad = g_pow_p(nonce); // g^R mod p
        unique_ptr<ElementModQ> exponent = nullptr;
        if (m == 0) {
            exponent = nonce.clone(); // (V+0)
        } else if (m == 1) {
            exponent = add_mod_q(nonce, ONE_MOD_Q()); // (V+1)
        } else {
            exponent = add_mod_q(nonce, *ElementModQ::fromUint64(m)); // (V+R)
        }

        auto data = pow_mod_p(publicKey, *exponent); // K^(V+R) mod p

        Log::trace("Base-K Generated Encryption");
        Log::trace("publicKey", publicKey.toHex());
        Log::trace("pad", pad->toHex());
        Log::trace("data", data->toHex());

        return make_unique<ElGamalCiphertext>(move(pad), move(data));
    }

    unique_ptr<ElGamalCiphertext> elgamalEncrypt(uint64_t m, const ElementModQ &nonce,
                                                 const ElementModP &publicKey,
                                                 const ElementModP &encryptionBase)
    {
        // E.G. 1.0 Compatible ElGamal Encrypt.
        // (g^R mod p, B^V ·K^R mod p)

        if (publicKey == encryptionBase) {
            return elgamalEncrypt(m, nonce, publicKey);
        }

        auto pad = g_pow_p(nonce);                         // g^R
        auto blindingFactor = pow_mod_p(publicKey, nonce); // K^R
        return elgamalEncrypt(m, move(pad), *blindingFactor, publicKey, encryptionBase);
    }

    unique_ptr<ElGamalCiphertext> elgamalEncrypt(uint64_t m, const ElementModP &publicKey,
                                                 const PrecomputedEncryption &precomputedValues)
    {
        // E.G 2.0 Encrypt using precomputed values.
        // (g^R mod p, K^V ·K^R mod p) = (g^R mod p, K^(V+R) mod p)

        auto pad = precomputedValues.getPad()->clone();              // g^R mod p
        auto blindingFactor = precomputedValues.getBlindingFactor(); // K^R mod p
        return elgamalEncrypt(m, move(pad), *blindingFactor, publicKey, publicKey);
    }

    unique_ptr<ElGamalCiphertext>
    elgamalAdd(const vector<reference_wrapper<ElGamalCiphertext>> &ciphertexts)
    {
        if (ciphertexts.empty()) {
            throw invalid_argument("must have one or more ciphertexts");
        }

        auto resultPad = ElementModP::fromUint64(1UL);
        auto resultData = ElementModP::fromUint64(1UL);
        for (auto ciphertext : ciphertexts) {
            auto pad = mul_mod_p(*resultPad, *ciphertext.get().getPad());
            resultPad.swap(pad);
            auto data = mul_mod_p(*resultData, *ciphertext.get().getData());
            resultData.swap(data);
        }
        return make_unique<ElGamalCiphertext>(move(resultPad), move(resultData));
    }

    unique_ptr<ElGamalCiphertext> elgamalAdd(const ElGamalCiphertext &a, const ElGamalCiphertext &b)
    {
        auto pad = mul_mod_p(*a.getPad(), *b.getPad());
        auto data = mul_mod_p(*a.getData(), *b.getData());
        return make_unique<ElGamalCiphertext>(move(pad), move(data));
    }

#pragma region HashedElGamalCiphertext

    struct HashedElGamalCiphertext::Impl {
        unique_ptr<ElementModP> pad;
        vector<uint8_t> data;
        vector<uint8_t> mac;

        Impl(unique_ptr<ElementModP> pad, vector<uint8_t> data, vector<uint8_t> mac)
            : pad(move(pad)), data(data), mac(mac)
        {
        }

        [[nodiscard]] unique_ptr<HashedElGamalCiphertext::Impl> clone() const
        {
            auto _pad = make_unique<ElementModP>(*pad);
            return make_unique<HashedElGamalCiphertext::Impl>(move(_pad), data, mac);
        }

        [[nodiscard]] unique_ptr<ElementModQ> crypto_hash() const
        {
            return hash_elems({pad.get(), data, mac});
        }

        bool operator==(const Impl &other)
        {
            return *pad == *other.pad && data == other.data && mac == other.mac;
        }
    };

    // Lifecycle Methods

    HashedElGamalCiphertext::HashedElGamalCiphertext(const HashedElGamalCiphertext &other)
        : pimpl(other.pimpl->clone())
    {
    }

    HashedElGamalCiphertext::HashedElGamalCiphertext(std::unique_ptr<ElementModP> pad,
                                                     std::vector<uint8_t> data,
                                                     std::vector<uint8_t> mac)
        : pimpl(new Impl(move(pad), data, mac))
    {
    }

    HashedElGamalCiphertext::~HashedElGamalCiphertext() = default;

    // Operator Overloads

    HashedElGamalCiphertext &HashedElGamalCiphertext::operator=(HashedElGamalCiphertext rhs)
    {
        swap(pimpl, rhs.pimpl);
        return *this;
    }

    bool HashedElGamalCiphertext::operator==(const HashedElGamalCiphertext &other)
    {
        return *pimpl == *other.pimpl;
    }

    bool HashedElGamalCiphertext::operator!=(const HashedElGamalCiphertext &other)
    {
        return !(*this == other);
    }

    // Property Getters

    ElementModP *HashedElGamalCiphertext::getPad() { return pimpl->pad.get(); }
    ElementModP *HashedElGamalCiphertext::getPad() const { return pimpl->pad.get(); }
    vector<uint8_t> HashedElGamalCiphertext::getData() { return pimpl->data; }
    vector<uint8_t> HashedElGamalCiphertext::getData() const { return pimpl->data; }
    vector<uint8_t> HashedElGamalCiphertext::getMac() { return pimpl->mac; }
    vector<uint8_t> HashedElGamalCiphertext::getMac() const { return pimpl->mac; }

    unique_ptr<ElementModQ> HashedElGamalCiphertext::crypto_hash() { return pimpl->crypto_hash(); }
    unique_ptr<ElementModQ> HashedElGamalCiphertext::crypto_hash() const
    {
        return pimpl->crypto_hash();
    }

    // Public Methods

    unique_ptr<HashedElGamalCiphertext> HashedElGamalCiphertext::make(const ElementModP &pad,
                                                                      std::vector<uint8_t> data,
                                                                      std::vector<uint8_t> mac)
    {
        return make_unique<HashedElGamalCiphertext>(make_unique<ElementModP>(pad), data, mac);
    }

    vector<uint8_t> HashedElGamalCiphertext::decrypt(const ElementModP &publicKey,
                                                     const ElementModQ &secretKey,
                                                     const string &hashPrefix,
                                                     const ElementModQ &seed, bool expectPadding)
    {
        // Note this decryption method is primarily used for testing
        vector<uint8_t> plaintext_with_padding;
        vector<uint8_t> plaintext;

        uint32_t ciphertext_len = pimpl->data.size();
        uint32_t number_of_blocks = ciphertext_len / HASHED_CIPHERTEXT_BLOCK_LENGTH;
        if ((0 != (ciphertext_len % HASHED_CIPHERTEXT_BLOCK_LENGTH)) || (ciphertext_len == 0)) {
            throw invalid_argument("HashedElGamalCiphertext::decrypt the ciphertext "
                                   "is not a multiple of the block length 32");
        }

        auto publicKey_to_r = pow_mod_p(*pimpl->pad, secretKey);

        // hash g_to_r and publicKey_to_r to get the session key (k)
        auto session_key = hash_elems({hashPrefix, &const_cast<ElementModQ &>(seed),
                                       &const_cast<ElementModP &>(publicKey), pimpl->pad.get(),
                                       publicKey_to_r.get()});

        vector<uint8_t> mac_key =
          HMAC::compute(session_key->toBytes(), seed.toBytes(),
                        number_of_blocks * HASHED_CIPHERTEXT_BLOCK_LENGTH_IN_BITS, 0);

        // calculate the mac (c0 is g ^ r mod p and c1 is the ciphertext, they are concatenated)
        vector<uint8_t> c0_and_c1(pimpl->pad->toBytes());
        c0_and_c1.insert(c0_and_c1.end(), pimpl->data.begin(), pimpl->data.end());
        vector<uint8_t> our_mac = HMAC::compute(mac_key, c0_and_c1, 0, 0);
        hacl::Lib::memZero(&mac_key.front(), mac_key.size());

        if (pimpl->mac != our_mac) {
            throw runtime_error(
              "HashedElGamalCiphertext::decrypt the calculated mac didn't match the passed in mac");
        }

        uint32_t plaintext_index = 0;
        for (uint32_t i = 0; i < number_of_blocks; i++) {
            vector<int8_t> temp_plaintext(HASHED_CIPHERTEXT_BLOCK_LENGTH, 0);

            vector<uint8_t> xor_key =
              HMAC::compute(session_key->toBytes(), seed.toBytes(),
                            number_of_blocks * HASHED_CIPHERTEXT_BLOCK_LENGTH_IN_BITS, i + 1);

            // XOR the key with the plaintext
            for (int j = 0; j < (int)HASHED_CIPHERTEXT_BLOCK_LENGTH; j++) {
                temp_plaintext[j] = pimpl->data[plaintext_index] ^ xor_key[j];
                // advance the plaintext index
                plaintext_index++;
            }
            hacl::Lib::memZero(&xor_key.front(), xor_key.size());

            plaintext_with_padding.insert(plaintext_with_padding.end(), temp_plaintext.begin(),
                                          temp_plaintext.end());
            hacl::Lib::memZero(&temp_plaintext.front(), temp_plaintext.size());
        }

        if (expectPadding) {
            uint16_t pad_len_be;
            memcpy(&pad_len_be, &plaintext_with_padding.front(), sizeof(pad_len_be));
            uint16_t pad_len = be16toh(pad_len_be);

            if (pad_len > (plaintext_with_padding.size() - sizeof(pad_len))) {
                throw runtime_error(
                  "HashedElGamalCiphertext::decrypt the padding is incorrect, decrypt failed");
            }

            // check that the end bytes are 0x00
            if (pad_len > 0) {
                for (int i = 1; i <= (int)pad_len; i++) {
                    if (plaintext_with_padding[plaintext_with_padding.size() - i] != 0x00) {
                        throw runtime_error("HashedElGamalCiphertext::decrypt the padding is "
                                            "incorrect, decrypt failed");
                    }
                }
            }

            plaintext.insert(plaintext.end(), &plaintext_with_padding.front() + sizeof(pad_len),
                             &plaintext_with_padding.front() +
                               (plaintext_with_padding.size() - pad_len));
        } else {
            plaintext = plaintext_with_padding;
        }

        return plaintext;
    }

    /// <Summary>
    /// Partially Decrypts an ElGamal ciphertext with a known ElGamal secret key.
    /// 𝑀_i = C0^P𝑖 mod 𝑝 in the spec
    ///
    /// <param name="secretKey">The corresponding ElGamal secret key.</param>
    /// <returns>A partial decryption of the plaintext value</returns
    /// </Summary>
    unique_ptr<ElementModP> HashedElGamalCiphertext::partialDecrypt(const ElementModQ &secretKey)
    {
        return pow_mod_p(*pimpl->pad, secretKey);
    }

    /// <Summary>
    /// Partially Decrypts an ElGamal ciphertext with a known ElGamal secret key.
    /// 𝑀_i = C0^P𝑖 mod 𝑝 in the spec
    ///
    /// <param name="secretKey">The corresponding ElGamal secret key.</param>
    /// <returns>A partial decryption of the plaintext value</returns
    /// </Summary>
    unique_ptr<ElementModP>
    HashedElGamalCiphertext::partialDecrypt(const ElementModQ &secretKey) const
    {
        return pow_mod_p(*pimpl->pad, secretKey);
    }

    unique_ptr<HashedElGamalCiphertext> HashedElGamalCiphertext::clone() const
    {
        return make_unique<HashedElGamalCiphertext>(pimpl->pad->clone(), pimpl->data, pimpl->mac);
    }

    unique_ptr<HashedElGamalCiphertext>
    HashedElGamalCiphertext::encryptBallotNonce(const ElementModQ *ballotNonce,
                                                const ElementModP *ballotDataKey,
                                                const ElementModQ *selectionEncId)
    {
        // 1. Random xi_hat_B; alpha_B = g^xi_hat_B, beta_B = K_hat^xi_hat_B
        auto xi_hat = rand_q();
        auto alpha = g_pow_p(*xi_hat);
        auto beta = pow_mod_p(*ballotDataKey, *xi_hat);

        // 2. h = H(H_I; 0x22, alpha_B, beta_B) — encryption key seed
        auto h = hash_elems_v21(selectionEncId, EG_DS_BALLOT_NONCE_ENC_KEY,
                                {alpha.get(), beta.get()});
        auto h_bytes = h->toBytes();
        if (h_bytes.size() < 32) {
            h_bytes.insert(h_bytes.begin(), 32 - h_bytes.size(), 0x00);
        }

        // 3. KDF: derive 1 key
        const std::string ctx_label("ballot_nonce_encrypt");
        std::vector<uint8_t> context(ctx_label.begin(), ctx_label.end());
        auto keys = KDF::derive(h_bytes, "ballot_nonce", context, 1);
        const auto &k1 = keys[0];

        // 4. XOR encrypt: C_1 = bytes(xi_B, 32) XOR k_1
        auto nonce_bytes = ballotNonce->toBytes();
        if (nonce_bytes.size() < 32) {
            nonce_bytes.insert(nonce_bytes.begin(), 32 - nonce_bytes.size(), 0x00);
        } else if (nonce_bytes.size() > 32) {
            nonce_bytes.erase(nonce_bytes.begin(),
                              nonce_bytes.begin() + (nonce_bytes.size() - 32));
        }

        vector<uint8_t> c1(32);
        for (size_t i = 0; i < 32; ++i) {
            c1[i] = nonce_bytes[i] ^ k1[i];
        }

        // 5. Schnorr proof: prove knowledge of xi_hat_B
        auto u = rand_q();
        auto h_commit = g_pow_p(*u); // g^u_B

        // c_B = H_q(H_I; 0x23, g^u_B, alpha_B, C_1)
        auto c = hash_elems_v21_q(selectionEncId, EG_DS_BALLOT_NONCE_ENC_PROOF,
                                  {h_commit.get(), alpha.get(), c1});
        auto v = a_minus_bc_mod_q(*u, *c, *xi_hat);

        // Encode proof as: challenge (32 bytes) || response (32 bytes) = 64 bytes
        auto c_bytes = c->toBytes();
        auto v_bytes = v->toBytes();
        if (c_bytes.size() < 32) {
            c_bytes.insert(c_bytes.begin(), 32 - c_bytes.size(), 0x00);
        }
        if (v_bytes.size() < 32) {
            v_bytes.insert(v_bytes.begin(), 32 - v_bytes.size(), 0x00);
        }

        vector<uint8_t> proof;
        proof.insert(proof.end(), c_bytes.begin(), c_bytes.end());
        proof.insert(proof.end(), v_bytes.begin(), v_bytes.end());

        return make_unique<HashedElGamalCiphertext>(move(alpha), move(c1), move(proof));
    }

    unique_ptr<ElementModQ>
    HashedElGamalCiphertext::decryptBallotNonce(const ElementModQ *secretKey,
                                                const ElementModQ *selectionEncId) const
    {
        // Recompute beta = alpha^secretKey (DH property: equals K_hat^xi_hat)
        auto beta = pow_mod_p(*getPad(), *secretKey);

        // h = H(H_I; 0x22, alpha, beta)
        auto h = hash_elems_v21(selectionEncId, EG_DS_BALLOT_NONCE_ENC_KEY,
                                {const_cast<ElementModP *>(getPad()), beta.get()});
        auto h_bytes = h->toBytes();
        if (h_bytes.size() < 32) {
            h_bytes.insert(h_bytes.begin(), 32 - h_bytes.size(), 0x00);
        }

        // KDF: derive 1 key
        const std::string ctx_label("ballot_nonce_encrypt");
        std::vector<uint8_t> context(ctx_label.begin(), ctx_label.end());
        auto keys = KDF::derive(h_bytes, "ballot_nonce", context, 1);
        const auto &k1 = keys[0];

        // XOR decrypt
        auto data = getData();
        vector<uint8_t> nonce_bytes(32);
        for (size_t i = 0; i < 32; ++i) {
            nonce_bytes[i] = data[i] ^ k1[i];
        }

        return bytes_to_q(nonce_bytes, true);
    }

    bool HashedElGamalCiphertext::isNonceProofValid(const ElementModP *ballotDataKey,
                                                    const ElementModQ *selectionEncId) const
    {
        auto proof = getMac(); // 64 bytes: challenge || response
        if (proof.size() != 64) {
            return false;
        }

        vector<uint8_t> c_bytes(proof.begin(), proof.begin() + 32);
        vector<uint8_t> v_bytes(proof.begin() + 32, proof.end());

        auto c = bytes_to_q(c_bytes, true);
        auto v = bytes_to_q(v_bytes, true);

        // Recompute h' = g^v * alpha^c
        auto gv = g_pow_p(*v);
        auto alphac = pow_mod_p(*getPad(), *c);
        auto h_prime = mul_mod_p(*gv, *alphac);

        // c' = H_q(H_I; 0x23, h', alpha, C_1)
        auto data = getData();
        auto c_prime =
          hash_elems_v21_q(selectionEncId, EG_DS_BALLOT_NONCE_ENC_PROOF,
                           {h_prime.get(), const_cast<ElementModP *>(getPad()), data});

        return *c_prime == *c;
    }

    unique_ptr<HashedElGamalCiphertext>
    HashedElGamalCiphertext::encryptContestData(const vector<uint8_t> &contestData,
                                                const ElementModP *ballotDataKey,
                                                const ElementModQ *selectionEncId,
                                                uint64_t contestIndex,
                                                const ElementModQ *ballotNonce)
    {
        if (contestData.empty() || (contestData.size() % 32) != 0) {
            throw invalid_argument("encryptContestData: data must be a non-empty multiple of 32 bytes");
        }
        uint32_t number_of_blocks = contestData.size() / 32;

        // Step 1: xi = H_q(H_I; 0x25, ind_c, xi_B)
        auto xi = hash_elems_v21_q(selectionEncId, EG_DS_CONTEST_DATA_NONCE,
                                   {contestIndex,
                                    const_cast<ElementModQ *>(ballotNonce)});

        // Step 2: alpha = g^xi, beta = K_hat^xi
        auto alpha = g_pow_p(*xi);
        auto beta = pow_mod_p(*ballotDataKey, *xi);

        // Step 3: h = H(H_I; 0x26, ind_c, alpha, beta)
        auto h = hash_elems_v21(selectionEncId, EG_DS_CONTEST_DATA_ENC_KEY,
                                {contestIndex, alpha.get(), beta.get()});
        auto h_bytes = h->toBytes();
        if (h_bytes.size() < 32) {
            h_bytes.insert(h_bytes.begin(), 32 - h_bytes.size(), 0x00);
        }

        // Step 4: KDF — context = "contest_data" || be32(ind_c)
        const std::string ctx_str("contest_data");
        std::vector<uint8_t> kdf_context(ctx_str.begin(), ctx_str.end());
        kdf_context.push_back(static_cast<uint8_t>((contestIndex >> 24) & 0xFF));
        kdf_context.push_back(static_cast<uint8_t>((contestIndex >> 16) & 0xFF));
        kdf_context.push_back(static_cast<uint8_t>((contestIndex >> 8)  & 0xFF));
        kdf_context.push_back(static_cast<uint8_t>( contestIndex        & 0xFF));
        auto keys = KDF::derive(h_bytes, "data_enc_keys", kdf_context, number_of_blocks);

        // Step 5: XOR-encrypt each 32-byte block
        vector<uint8_t> c1;
        c1.reserve(contestData.size());
        for (uint32_t i = 0; i < number_of_blocks; ++i) {
            const auto &ki = keys[i];
            for (size_t j = 0; j < 32; ++j) {
                c1.push_back(contestData[i * 32 + j] ^ ki[j]);
            }
        }

        // Step 6: Schnorr proof — prove knowledge of xi
        auto u = rand_q();
        auto commit = g_pow_p(*u); // g^u

        // c = H_q(H_I; 0x27, ind_c, g^u, alpha, C_1)
        auto c = hash_elems_v21_q(selectionEncId, EG_DS_CONTEST_DATA_ENC_PROOF,
                                  {contestIndex, commit.get(), alpha.get(), c1});
        auto v = a_minus_bc_mod_q(*u, *c, *xi);

        // Encode proof as challenge(32) || response(32) = 64 bytes
        auto c_bytes = c->toBytes();
        auto v_bytes = v->toBytes();
        if (c_bytes.size() < 32) {
            c_bytes.insert(c_bytes.begin(), 32 - c_bytes.size(), 0x00);
        }
        if (v_bytes.size() < 32) {
            v_bytes.insert(v_bytes.begin(), 32 - v_bytes.size(), 0x00);
        }
        vector<uint8_t> proof;
        proof.insert(proof.end(), c_bytes.begin(), c_bytes.end());
        proof.insert(proof.end(), v_bytes.begin(), v_bytes.end());

        return make_unique<HashedElGamalCiphertext>(move(alpha), move(c1), move(proof));
    }

    vector<uint8_t>
    HashedElGamalCiphertext::decryptContestData(const ElementModQ *secretKey,
                                                const ElementModQ *selectionEncId,
                                                uint64_t contestIndex) const
    {
        auto data = getData();
        if (data.empty() || (data.size() % 32) != 0) {
            throw invalid_argument("decryptContestData: ciphertext must be a non-empty multiple of 32 bytes");
        }
        uint32_t number_of_blocks = data.size() / 32;

        // Step 1: beta = alpha^secretKey
        auto beta = pow_mod_p(*getPad(), *secretKey);

        // Step 2: h = H(H_I; 0x26, ind_c, alpha, beta)
        auto h = hash_elems_v21(selectionEncId, EG_DS_CONTEST_DATA_ENC_KEY,
                                {contestIndex,
                                 const_cast<ElementModP *>(getPad()),
                                 beta.get()});
        auto h_bytes = h->toBytes();
        if (h_bytes.size() < 32) {
            h_bytes.insert(h_bytes.begin(), 32 - h_bytes.size(), 0x00);
        }

        // Step 3: KDF — same params as encrypt
        const std::string ctx_str("contest_data");
        std::vector<uint8_t> kdf_context(ctx_str.begin(), ctx_str.end());
        kdf_context.push_back(static_cast<uint8_t>((contestIndex >> 24) & 0xFF));
        kdf_context.push_back(static_cast<uint8_t>((contestIndex >> 16) & 0xFF));
        kdf_context.push_back(static_cast<uint8_t>((contestIndex >> 8)  & 0xFF));
        kdf_context.push_back(static_cast<uint8_t>( contestIndex        & 0xFF));
        auto keys = KDF::derive(h_bytes, "data_enc_keys", kdf_context, number_of_blocks);

        // Step 4: XOR-decrypt each 32-byte block
        vector<uint8_t> plaintext;
        plaintext.reserve(data.size());
        for (uint32_t i = 0; i < number_of_blocks; ++i) {
            const auto &ki = keys[i];
            for (size_t j = 0; j < 32; ++j) {
                plaintext.push_back(data[i * 32 + j] ^ ki[j]);
            }
        }

        return plaintext;
    }

    bool HashedElGamalCiphertext::isContestDataProofValid(const ElementModP *ballotDataKey,
                                                          const ElementModQ *selectionEncId,
                                                          uint64_t contestIndex) const
    {
        auto proof = getMac(); // 64 bytes: challenge || response
        if (proof.size() != 64) {
            return false;
        }

        vector<uint8_t> c_bytes(proof.begin(), proof.begin() + 32);
        vector<uint8_t> v_bytes(proof.begin() + 32, proof.end());

        auto c = bytes_to_q(c_bytes, true);
        auto v = bytes_to_q(v_bytes, true);

        // h' = g^v * alpha^c
        auto gv     = g_pow_p(*v);
        auto alphac = pow_mod_p(*getPad(), *c);
        auto h_prime = mul_mod_p(*gv, *alphac);

        // c' = H_q(H_I; 0x27, ind_c, h', alpha, C_1)
        auto data = getData();
        auto c_prime =
          hash_elems_v21_q(selectionEncId, EG_DS_CONTEST_DATA_ENC_PROOF,
                           {contestIndex, h_prime.get(),
                            const_cast<ElementModP *>(getPad()),
                            data});

        return *c_prime == *c;
    }

#pragma endregion // HashedElGamalCiphertext

    vector<uint8_t> formatMessage(vector<uint8_t> message,
                                  HASHED_CIPHERTEXT_PADDED_DATA_SIZE max_len, bool allow_truncation)
    {
        if (max_len == 0 || max_len > HASHED_CIPHERTEXT_PADDED_DATA_SIZE::BYTES_512) {
            throw invalid_argument("HashedElGamalCiphertext::encrypt max_len is invalid");
        }

        // TODO: HACK: ISSUE #358: we need to check the modulo of the max_len matches the block length
        // and handle the indicator size truncation inline inside this function

        // padding scheme is to concatenate [length of the padding][plaintext][padding bytes of 0x00]
        // padding bytes 0x00 are padded out to the first HASHED_CIPHERTEXT_BLOCK_LENGTH boundary
        // past max_len. So if max_len is 62 then it will pad to the 64 byte boundary

        vector<uint8_t> formattedMessage;

        uint16_t pad_len = 0;
        uint16_t pad_len_be = 0;

        if (allow_truncation && (message.size() > max_len)) {
            // truncate the data
            // insert length in big endian form
            formattedMessage.insert(formattedMessage.end(), (uint8_t *)&pad_len_be,
                                    (uint8_t *)&pad_len_be + sizeof(pad_len_be));
            // insert plaintext
            formattedMessage.insert(formattedMessage.end(), &message.front(),
                                    &message.front() + max_len);
        } else {
            if (message.size() > max_len) {
                throw invalid_argument(
                  "HashedElGamalCiphertext::encrypt the plaintext is greater than max_len");
            }

            uint16_t pad_len = max_len - message.size();
            uint16_t pad_len_be = htobe16(pad_len);

            std::vector<uint8_t> padding(pad_len, 0);

            // insert length in big endian form
            formattedMessage.insert(formattedMessage.end(), (uint8_t *)&pad_len_be,
                                    (uint8_t *)&pad_len_be + sizeof(pad_len_be));
            // insert plaintext
            formattedMessage.insert(formattedMessage.end(), message.begin(), message.end());

            // we dont pad 0x00s if the length field plus plaintext length falls on a block length boundary
            if (pad_len > 0) {
                // insert padding
                formattedMessage.insert(formattedMessage.end(), padding.begin(), padding.end());
            }
        }

        return formattedMessage;
    }

    unique_ptr<HashedElGamalCiphertext>
    hashedElgamalEncrypt(std::vector<uint8_t> message, const ElementModQ &nonce,
                         const std::string &hashPrefix, const ElementModP &publicKey,
                         const ElementModQ &seed, bool usePrecompute /* = false */)
    {

        if (0 != (message.size() % HASHED_CIPHERTEXT_BLOCK_LENGTH)) {
            throw invalid_argument("HashedElGamalCiphertext::encrypt the apply_padding was false "
                                   "but the plaintext is not a multiple of the block length 32");
        }

        vector<uint8_t> plaintext_on_boundary;
        plaintext_on_boundary.insert(plaintext_on_boundary.end(), message.begin(), message.end());

        unique_ptr<ElementModP> alpha = nullptr; // g^Ri,l mod p
        unique_ptr<ElementModP> beta = nullptr;  // K^Ri,l mod p

        if (usePrecompute) {
            // check if the are precompute values rather than doing the exponentiations here
            auto triple = PrecomputeBufferContext::popPrecomputedEncryption();
            if (triple != nullptr && triple.has_value()) {
                alpha = triple.value()->getPad()->clone();
                beta = triple.value()->getBlindingFactor()->clone();
            }
        }

        // fallback to doing the exponentiations here
        if (alpha == nullptr || beta == nullptr) {
            alpha = g_pow_p(nonce);
            beta = pow_mod_p(publicKey, nonce);
        }

        // hash g_to_r and publicKey_to_r to get the session key (k_i,l)
        auto session_key =
          hash_elems({hashPrefix, &const_cast<ElementModQ &>(seed),
                      &const_cast<ElementModP &>(publicKey), alpha.get(), beta.get()});

        uint32_t plaintext_index = 0;
        uint32_t plaintext_len = plaintext_on_boundary.size();
        uint32_t number_of_blocks = plaintext_len / HASHED_CIPHERTEXT_BLOCK_LENGTH;

        vector<uint8_t> ciphertext;
        for (uint32_t i = 0; i < number_of_blocks; i++) {
            vector<uint8_t> temp_ciphertext(HASHED_CIPHERTEXT_BLOCK_LENGTH, 0);

            vector<uint8_t> xor_key =
              HMAC::compute(session_key->toBytes(), seed.toBytes(),
                            number_of_blocks * HASHED_CIPHERTEXT_BLOCK_LENGTH_IN_BITS, i + 1);

            // XOR the key with the plaintext
            for (int j = 0; j < (int)HASHED_CIPHERTEXT_BLOCK_LENGTH; j++) {
                temp_ciphertext[j] = plaintext_on_boundary[plaintext_index] ^ xor_key[j];
                // advance the plaintext index
                plaintext_index++;
            }
            hacl::Lib::memZero(&xor_key.front(), xor_key.size());

            ciphertext.insert(ciphertext.end(), temp_ciphertext.begin(), temp_ciphertext.end());
            hacl::Lib::memZero(&temp_ciphertext.front(), temp_ciphertext.size());
        }

        vector<uint8_t> mac_key =
          HMAC::compute(session_key->toBytes(), seed.toBytes(),
                        number_of_blocks * HASHED_CIPHERTEXT_BLOCK_LENGTH_IN_BITS, 0);

        // calculate the mac (c0 is g ^ r mod p and c1 is the ciphertext, they are concatenated)
        vector<uint8_t> c0_and_c1(alpha->toBytes());
        c0_and_c1.insert(c0_and_c1.end(), ciphertext.begin(), ciphertext.end());
        vector<uint8_t> mac = HMAC::compute(mac_key, c0_and_c1, 0, 0);
        hacl::Lib::memZero(&mac_key.front(), mac_key.size());

        return make_unique<HashedElGamalCiphertext>(move(alpha), ciphertext, mac);
    }

    unique_ptr<HashedElGamalCiphertext>
    hashedElgamalEncrypt(std::vector<uint8_t> message, const ElementModQ &nonce,
                         const std::string &hashPrefix, const ElementModP &publicKey,
                         const ElementModQ &seed, HASHED_CIPHERTEXT_PADDED_DATA_SIZE max_len,
                         bool allowTruncation, bool usePrecompute /* = false */)
    {
        vector<uint8_t> formattedMessage = formatMessage(message, max_len, allowTruncation);
        return hashedElgamalEncrypt(formattedMessage, nonce, hashPrefix, publicKey, seed,
                                    usePrecompute);
    }

} // namespace electionguard
