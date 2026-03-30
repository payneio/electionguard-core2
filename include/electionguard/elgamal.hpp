#ifndef __ELECTIONGUARD__CPP_ELGAMAL_HPP_INCLUDED__
#define __ELECTIONGUARD__CPP_ELGAMAL_HPP_INCLUDED__
#include "crypto_hashable.hpp"
#include "export.h"
#include "group.hpp"
#include "precompute_buffers.hpp"

#include <memory>
#include <vector>

namespace electionguard
{
    /// <summary>
    /// An exponential ElGamal keypair.
    /// </summary>
    class EG_API ElGamalKeyPair
    {
      public:
        ElGamalKeyPair(const ElGamalKeyPair &other);
        ElGamalKeyPair(const ElGamalKeyPair &&other);
        ElGamalKeyPair(std::unique_ptr<ElementModQ> secretKey,
                       std::unique_ptr<ElementModP> publicKey);
        ~ElGamalKeyPair();

        ElGamalKeyPair &operator=(ElGamalKeyPair rhs);
        ElGamalKeyPair &operator=(ElGamalKeyPair &&rhs);

        /// <Summary>
        /// The ElGamal Secret Key.
        /// </Summary>
        ElementModQ *getSecretKey();

        /// <Summary>
        /// The ElGamal Secret Key.
        /// </Summary>
        ElementModQ *getSecretKey() const;

        /// <Summary>
        /// The ElGamal Public Key.
        /// </Summary>
        ElementModP *getPublicKey();

        /// <Summary>
        /// The ElGamal Public Key.
        /// </Summary>
        ElementModP *getPublicKey() const;

        /// <Summary>
        /// Make an elgamal keypair from a secret.
        /// </Summary>
        static std::unique_ptr<ElGamalKeyPair> fromSecret(const ElementModQ &secretKey,
                                                          bool isFixedBase = true);

        static std::unique_ptr<ElGamalKeyPair> fromPair(const ElementModQ &secretKey,
                                                        const ElementModP &publicKeyData);

      private:
        class Impl;
#pragma warning(suppress : 4251)
        std::unique_ptr<Impl> pimpl;
    };

    /// <summary>
    /// An "exponential ElGamal ciphertext" (i.e., with the plaintext in the exponent to allow for
    /// homomorphic addition). Create one with `elgamal_encrypt`. Add them with `elgamal_add`.
    /// Decrypt using one of the supplied instance methods.
    /// </summary>
    class EG_API ElGamalCiphertext : public CryptoHashable
    {
      public:
        ElGamalCiphertext(const ElGamalCiphertext &other);
        ElGamalCiphertext(ElGamalCiphertext &&other);
        ElGamalCiphertext(std::unique_ptr<ElementModP> pad, std::unique_ptr<ElementModP> data);
        ~ElGamalCiphertext();

        ElGamalCiphertext &operator=(ElGamalCiphertext rhs);
        ElGamalCiphertext &operator=(ElGamalCiphertext &&rhs);
        bool operator==(const ElGamalCiphertext &other);
        bool operator!=(const ElGamalCiphertext &other);

        /// <Summary>
        /// The pad value also referred to as A, a, 𝑎, or alpha in the spec.
        /// </Summary>
        ElementModP *getPad();

        /// <Summary>
        /// The pad value also referred to as A, a, 𝑎, or alpha in the spec.
        /// </Summary>
        ElementModP *getPad() const;

        /// <Summary>
        /// The data value also referred to as B, b, 𝛽, or beta in the spec.
        /// </Summary>
        ElementModP *getData();

        /// <Summary>
        /// The data value also referred to as B, b, 𝛽, or beta in the spec.
        /// </Summary>
        ElementModP *getData() const;

        virtual std::unique_ptr<ElementModQ> crypto_hash() override;
        virtual std::unique_ptr<ElementModQ> crypto_hash() const override;

        /// <Summary>
        /// Make an ElGamal Ciphertext from the given pad and data
        /// </Summary>
        static std::unique_ptr<ElGamalCiphertext> make(const ElementModP &pad,
                                                       const ElementModP &data);

        /// <summary>
        /// Homomorphically accumulates other ElGamal ciphertext by pairwise multiplication
        /// and returns the result without modifying the original.
        /// </summary>
        std::unique_ptr<ElGamalCiphertext> elgamalAdd(const ElGamalCiphertext &b);

        /// <summary>
        /// Homomorphically accumulates another ElGamal ciphertext by pairwise multiplication
        /// and returns the result without modifying the original.
        /// </summary>
        std::unique_ptr<ElGamalCiphertext>
        elgamalAdd(const std::vector<std::reference_wrapper<ElGamalCiphertext>> &ciphertexts);

        /// <Summary>
        /// Decrypts an ElGamal ciphertext with an "accumulation" (the product of partial decryptions).
        /// Calculates 𝑀=𝐵⁄(∏𝑀𝑖) mod 𝑝.
        ///
        /// <param name="shareAccumulation">The accumulation of shares (∏𝑀𝑖).</param>
        /// <param name="base">The base value used to encrypt the ciphertext.</param>
        /// <returns>An exponentially encoded plaintext message.</returns
        /// </Summary>
        uint64_t decrypt(const ElementModP &shareAccumulation, const ElementModP &base);

        /// <Summary>
        /// Decrypts an ElGamal ciphertext with an "accumulation" (the product of partial decryptions).
        ///
        /// <param name="shareAccumulation">The accumulation of shares (∏𝑀𝑖).</param>
        /// <param name="base">The base value used to encrypt the ciphertext.</param>
        /// <returns>An exponentially encoded plaintext message.</returns
        /// </Summary>
        uint64_t decrypt(const ElementModP &shareAccumulation, const ElementModP &base) const;

        /// <Summary>
        /// Decrypt the ciphertext directly using the provided secret key.
        ///
        /// This is a convenience accessor useful for some use cases.
        /// This method should not be used by consumers operating in live secret ballot elections.
        ///
        /// <param name="secretKey">The corresponding ElGamal secret key.</param>
        /// <param name="base">The base value used to encrypt the ciphertext.</param>
        /// <returns>An exponentially encoded plaintext message.</returns
        /// </Summary>
        uint64_t decrypt(const ElementModQ &secretKey, const ElementModP &base);

        /// <Summary>
        /// Decrypt the ciphertext directly using the provided secret key.
        ///
        /// This is a convenience accessor useful for some use cases.
        /// This method should not be used by consumers operating in live secret ballot elections.
        ///
        /// <param name="secretKey">The corresponding ElGamal secret key.</param>
        /// <param name="base">The base value used to encrypt the ciphertext.</param>
        /// <returns>An exponentially encoded plaintext message.</returns
        /// </Summary>
        uint64_t decrypt(const ElementModQ &secretKey, const ElementModP &base) const;

        /// <Summary>
        /// Decrypt an ElGamal ciphertext using a known nonce and the ElGamal public key.
        ///
        /// This method is used primarily for decrypting against K for 2.0 elections
        ///
        /// <param name="publicKey">The corresponding ElGamal Public Key</param>
        /// <param name="nonce">The secret nonce used to create the ciphertext.</param>
        /// <returns>An exponentially encoded plaintext message.</returns
        /// </Summary>
        uint64_t decrypt(const ElementModP &publicKey, const ElementModQ &nonce);

        /// <Summary>
        /// Decrypt an ElGamal ciphertext using a known nonce and the ElGamal public key.
        ///
        /// This method is used primarily for decrypting against K for 2.0 elections
        ///
        /// <param name="publicKey">The corresponding ElGamal Public Key</param>
        /// <param name="nonce">The secret nonce used to create the ciphertext.</param>
        /// <returns>An exponentially encoded plaintext message.</returns
        /// </Summary>
        uint64_t decrypt(const ElementModP &publicKey, const ElementModQ &nonce) const;

        /// <Summary>
        /// Decrypt an ElGamal ciphertext using a known nonce and the ElGamal public key.
        ///
        /// This method is used primarily for decrypting against G for 1.0 elections
        ///
        /// <param name="publicKey">The corresponding ElGamal Public Key</param>
        /// <param name="nonce">The secret nonce used to create the ciphertext.</param>
        /// <returns>An exponentially encoded plaintext message.</returns
        /// </Summary>
        uint64_t decrypt(const ElementModP &publicKey, const ElementModQ &nonce,
                         const ElementModP &base);

        /// <Summary>
        /// Decrypt an ElGamal ciphertext using a known nonce and the ElGamal public key.
        ///
        /// This method is used primarily for decrypting against G for 1.0 elections
        ///
        /// <param name="publicKey">The corresponding ElGamal Public Key</param>
        /// <param name="nonce">The secret nonce used to create the ciphertext.</param>
        /// <returns>An exponentially encoded plaintext message.</returns
        /// </Summary>
        uint64_t decrypt(const ElementModP &publicKey, const ElementModQ &nonce,
                         const ElementModP &base) const;

        /// <Summary>
        /// Partially Decrypts an ElGamal ciphertext with a known ElGamal secret key.
        /// 𝑀_i = 𝐴^𝑠𝑖 mod 𝑝 in the spec
        ///
        /// <param name="secretKey">The corresponding ElGamal secret key.</param>
        /// <returns>A partial decryption of the plaintext value</returns
        /// </Summary>
        std::unique_ptr<ElementModP> partialDecrypt(const ElementModQ &secretKey);

        /// <Summary>
        /// Partially Decrypts an ElGamal ciphertext with a known ElGamal secret key.
        /// 𝑀_i = 𝐴^𝑠𝑖 mod 𝑝 in the spec
        ///
        /// <param name="secretKey">The corresponding ElGamal secret key.</param>
        /// <returns>A partial decryption of the plaintext value</returns
        /// </Summary>
        std::unique_ptr<ElementModP> partialDecrypt(const ElementModQ &secretKey) const;

        /// <Summary>
        /// Clone the value by making a deep copy.
        /// </Summary>
        std::unique_ptr<ElGamalCiphertext> clone() const;

        /// v2.1: Weighted accumulate: (A,B) = product(alpha_j^W_j, beta_j^W_j) mod p
        static std::unique_ptr<ElGamalCiphertext>
        weightedAccumulate(const std::vector<const ElGamalCiphertext *> &ciphertexts,
                           const std::vector<uint64_t> &weights);

      protected:
        /// <Summary>
        /// Decrypts an ElGamal ciphertext with a "known product" (the blinding factor used in the encryption).
        ///
        /// <param name="product">The known product (blinding factor).</param>
        /// <param name="base">The base value used to encrypt the ciphertext.</param>
        /// <returns>An exponentially encoded plaintext message.</returns
        /// </Summary>
        uint64_t decryptKnownProduct(const ElementModP &product, const ElementModP &base);

        /// <Summary>
        /// Decrypts an ElGamal ciphertext with a "known product" (the blinding factor used in the encryption).
        ///
        /// <param name="product">The known product (blinding factor).</param>
        /// <param name="base">The base value used to encrypt the ciphertext.</param>
        /// <returns>An exponentially encoded plaintext message.</returns
        /// </Summary>
        uint64_t decryptKnownProduct(const ElementModP &product, const ElementModP &base) const;

      private:
        class Impl;
#pragma warning(suppress : 4251)
        std::unique_ptr<Impl> pimpl;
    };

    /// <summary>
    /// Encrypts a message with a given random nonce and an ElGamal public key.
    ///
    /// This method is the "base-K" encruption method used primarily
    /// for encrypting against K for 2.0 elections.
    ///
    /// <param name="m">Message to elgamal_encrypt; must be an integer in [0,Q). Sometimes V or m or σ, in the spec.</param>
    /// <param name="nonce"> Randomly chosen nonce in [1,Q). (R, r or s or ξ in the spec)</param>
    /// <param name="publicKey"> ElGamal public key.</param>
    /// <returns>A ciphertext tuple.</returns>
    /// </summary>
    EG_API std::unique_ptr<ElGamalCiphertext>
    elgamalEncrypt(const uint64_t m, const ElementModQ &nonce, const ElementModP &publicKey);

    /// <summary>
    /// Encrypts a message with a given random nonce and an ElGamal public key.
    ///
    /// This method is used primarily for encrypting against G for 1.0 elections
    /// but can be used for encrypting against K for 2.0 elections, however it is
    /// more efficient to call the other overload of this method without the encryptionBase
    /// parameter for E.G. 2.0 elections.
    ///
    /// <param name="m">Message to elgamal_encrypt; must be an integer in [0,Q). Sometimes V or m, in the spec.</param>
    /// <param name="nonce">Randomly chosen nonce in [1,Q). (R, r, or s or ξ in the spec)</param>
    /// <param name="publicKey">ElGamal public key. (K in the spec)</param>
    /// <param name="encryptionBase"> The encryption base used to encrypt the ciphertext. (g or K in the spec)</param>
    EG_API std::unique_ptr<ElGamalCiphertext> elgamalEncrypt(const uint64_t m,
                                                             const ElementModQ &nonce,
                                                             const ElementModP &publicKey,
                                                             const ElementModP &encryptionBase);

    /// <summary>
    /// Encrypts a message with given precomputed values (two triples and a quadruple).
    /// However, only the first triple is used in this function.
    ///
    /// <param name="m">Message to elgamal_encrypt; must be an integer in [0,Q). Sometimes V or m or σ, in the spec.</param>
    /// <param name="precomputedValues">Precomputed encryption values. See Precompute Buffers.</param>
    /// <returns>A ciphertext tuple.</returns>
    /// </summary>
    EG_API std::unique_ptr<ElGamalCiphertext>
    elgamalEncrypt(uint64_t m, const ElementModP &publicKey,
                   const PrecomputedEncryption &precomputedValues);

    /// <summary>
    /// Homomorphically accumulates one or more ElGamal ciphertexts by pairwise multiplication.
    /// The exponents of vote counters will add.
    /// </summary>
    EG_API std::unique_ptr<ElGamalCiphertext>
    elgamalAdd(const std::vector<std::reference_wrapper<ElGamalCiphertext>> &ciphertexts);

    /// <summary>
    /// Homomorphically accumulates one or more ElGamal ciphertexts by pairwise multiplication.
    /// The exponents of vote counters will add.
    /// </summary>
    EG_API std::unique_ptr<ElGamalCiphertext> elgamalAdd(const ElGamalCiphertext &a,
                                                         const ElGamalCiphertext &b);

    /// <summary>
    /// A "Hashed ElGamal Ciphertext" as specified as the Auxiliary Encryption in
    /// the ElectionGuard specification. The tuple g^r mod p concatenated with
    /// K^r mod p are used to feed into a hash function to generate a main (session) key
    /// from which other keys derive to perform XOR encryption and to MAC the
    /// result. Create one with `hashedElgamalEncrypt`. Decrypt using one of the
    /// 'decrypt' methods.
    /// </summary>
    class EG_API HashedElGamalCiphertext : public CryptoHashable
    {
      public:
        HashedElGamalCiphertext(const HashedElGamalCiphertext &other);
        HashedElGamalCiphertext(HashedElGamalCiphertext &&other);
        HashedElGamalCiphertext(std::unique_ptr<ElementModP> pad, std::vector<uint8_t> data,
                                std::vector<uint8_t> mac);
        ~HashedElGamalCiphertext();

        HashedElGamalCiphertext &operator=(HashedElGamalCiphertext rhs);
        HashedElGamalCiphertext &operator=(HashedElGamalCiphertext &&rhs);
        bool operator==(const HashedElGamalCiphertext &other);
        bool operator!=(const HashedElGamalCiphertext &other);

        /// <Summary>
        /// The g^r mod p value also referred to as pad in the code and
        /// c0, 𝑎, or alpha in the spec.
        /// </Summary>
        ElementModP *getPad();

        /// <Summary>
        /// The g^r mod p value also referred to as pad in the code and
        /// c0, 𝑎, or alpha in the spec.
        /// </Summary>
        ElementModP *getPad() const;

        /// <Summary>
        /// The vector of encrypted ciphertext bytes. Referred to as c1
        /// in the spec.
        /// </Summary>
        std::vector<uint8_t> getData();

        /// <Summary>
        /// The vector of encrypted ciphertext bytes. Referred to as c1
        /// in the spec.
        /// </Summary>
        std::vector<uint8_t> getData() const;

        /// <Summary>
        /// The vector of MAC bytes. Referred to as c2 in the spec.
        /// </Summary>
        std::vector<uint8_t> getMac();

        /// <Summary>
        /// The vector of MAC bytes. Referred to as c2 in the spec.
        /// </Summary>
        std::vector<uint8_t> getMac() const;

        virtual std::unique_ptr<ElementModQ> crypto_hash() override;
        virtual std::unique_ptr<ElementModQ> crypto_hash() const override;

        static std::unique_ptr<HashedElGamalCiphertext>
        make(const ElementModP &pad, std::vector<uint8_t> data, std::vector<uint8_t> mac);

        /// <summary>
        /// Decrypts ciphertext with the Auxiliary Encryption method (as specified in the
        /// ElectionGuard specification) given a random nonce, an ElGamal public key,
        /// and an encryption seed. The encrypt may be called to look for padding to
        /// verify and remove, in this case the plaintext will be smaller than
        /// the ciphertext, or not to look for padding in which case the
        /// plaintext will be the same size as the ciphertext.
        ///
        /// <param name="publicKey">ElGamal Public Key</param>
        /// <param name="secretKey">ElGamal secret key or nonce</param>
        /// <param name="hashPrefix">A prefix value for the hash used to create the session key.</param>
        /// <param name="seed">An encruption seed used to generate the session key.</param>
        /// <param name="expectPadding">Indicates if padding should be removed from the decrypted value.</param>
        /// <returns>A plaintext vector.</returns>
        /// </summary>
        std::vector<uint8_t> decrypt(const ElementModP &publicKey, const ElementModQ &secretKey,
                                     const std::string &hashPrefix, const ElementModQ &seed,
                                     bool expectPadding);

        /// <Summary>
        /// Partially Decrypts an ElGamal ciphertext with a known ElGamal secret key.
        /// 𝑀_i = C0^P𝑖 mod 𝑝 in the spec
        ///
        /// <param name="secretKey">The corresponding ElGamal secret key.</param>
        /// <returns>A partial decryption of the plaintext value</returns
        /// </Summary>
        std::unique_ptr<ElementModP> partialDecrypt(const ElementModQ &secretKey);

        /// <Summary>
        /// Partially Decrypts an ElGamal ciphertext with a known ElGamal secret key.
        /// 𝑀_i = C0^P𝑖 mod 𝑝 in the spec
        ///
        /// <param name="secretKey">The corresponding ElGamal secret key.</param>
        /// <returns>A partial decryption of the plaintext value</returns
        /// </Summary>
        std::unique_ptr<ElementModP> partialDecrypt(const ElementModQ &secretKey) const;

        /// <Summary>
        /// Clone the value by making a deep copy.
        /// </Summary>
        std::unique_ptr<HashedElGamalCiphertext> clone() const;

        /// <summary>
        /// v2.1 ballot nonce encryption: signed hashed ElGamal with KDF.
        ///
        /// 1. Random xi_hat_B; (alpha_B, beta_B) = (g^xi_hat_B, K_hat^xi_hat_B)
        /// 2. h = H(H_I; 0x22, alpha_B, beta_B)
        /// 3. KDF: label "ballot_nonce", context "ballot_nonce_encrypt", derive 1 key
        /// 4. C_1 = bytes(xi_B, 32) XOR k_1
        /// 5. Schnorr proof: c_B = H_q(H_I; 0x23, g^u_B, C_0, C_1)
        ///
        /// <param name="ballotNonce">xi_B — the ballot nonce to encrypt.</param>
        /// <param name="ballotDataKey">K_hat — the joint data public key.</param>
        /// <param name="selectionEncId">H_I — the selection encryption identifier.</param>
        /// <returns>HashedElGamalCiphertext where pad=alpha_B, data=C_1, mac=proof bytes.</returns>
        /// </summary>
        static std::unique_ptr<HashedElGamalCiphertext>
        encryptBallotNonce(const ElementModQ *ballotNonce,
                           const ElementModP *ballotDataKey,
                           const ElementModQ *selectionEncId);

        /// <summary>
        /// v2.1 ballot nonce decryption: reverses encryptBallotNonce.
        ///
        /// Recomputes beta = alpha^secretKey, derives the same KDF key,
        /// and XOR-decrypts C_1 to recover xi_B.
        ///
        /// <param name="secretKey">The secret key corresponding to K_hat.</param>
        /// <param name="selectionEncId">H_I — must match the value used during encryption.</param>
        /// <returns>The decrypted ballot nonce xi_B.</returns>
        /// </summary>
        std::unique_ptr<ElementModQ>
        decryptBallotNonce(const ElementModQ *secretKey,
                           const ElementModQ *selectionEncId) const;

        /// <summary>
        /// Verify the Schnorr proof that the encryptor knew xi_hat_B.
        ///
        /// <param name="ballotDataKey">K_hat — the joint data public key.</param>
        /// <param name="selectionEncId">H_I — the selection encryption identifier.</param>
        /// <returns>true iff the proof is valid.</returns>
        /// </summary>
        bool isNonceProofValid(const ElementModP *ballotDataKey,
                               const ElementModQ *selectionEncId) const;

        /// <summary>
        /// v2.1 contest data encryption with K_hat via hashed ElGamal + KDF.
        ///
        /// 1. Nonce: xi = H_q(H_I; 0x25, ind_c, xi_B)
        /// 2. DH pair: (alpha, beta) = (g^xi, K_hat^xi)
        /// 3. Secret key: h = H(H_I; 0x26, ind_c, alpha, beta)
        /// 4. KDF: label "data_enc_keys", context "contest_data" || be32(ind_c), derive b keys
        /// 5. Ciphertext: C_0 = alpha, C_1 = D_1 XOR k_1 || ... || D_b XOR k_b
        /// 6. Schnorr proof: c = H_q(H_I; 0x27, ind_c, g^u, C_0, C_1)
        ///
        /// <param name="contestData">The plaintext data to encrypt (must be multiple of 32 bytes).</param>
        /// <param name="ballotDataKey">K_hat — the joint data public key.</param>
        /// <param name="selectionEncId">H_I — the selection encryption identifier.</param>
        /// <param name="contestIndex">ind_c — the contest index.</param>
        /// <param name="ballotNonce">xi_B — the ballot nonce.</param>
        /// <returns>HashedElGamalCiphertext where pad=alpha, data=ciphertext, mac=proof.</returns>
        /// </summary>
        static std::unique_ptr<HashedElGamalCiphertext>
        encryptContestData(const std::vector<uint8_t> &contestData,
                           const ElementModP *ballotDataKey,
                           const ElementModQ *selectionEncId,
                           uint64_t contestIndex,
                           const ElementModQ *ballotNonce);

        /// <summary>
        /// v2.1 contest data decryption: reverses encryptContestData.
        /// </summary>
        std::vector<uint8_t>
        decryptContestData(const ElementModQ *secretKey,
                           const ElementModQ *selectionEncId,
                           uint64_t contestIndex) const;

        /// <summary>
        /// Verify the Schnorr proof on contest data encryption.
        /// </summary>
        bool isContestDataProofValid(const ElementModP *ballotDataKey,
                                     const ElementModQ *selectionEncId,
                                     uint64_t contestIndex) const;

      private:
        class Impl;
#pragma warning(suppress : 4251)
        std::unique_ptr<Impl> pimpl;
    };

    /// <summary>
    /// Encrypts a message with the Auxiliary Encryption method (as specified in the
    /// ElectionGuard specification) given a random nonce, an ElGamal public key,
    /// and an encryption seed.
    ///
    /// The encrypt may be called to apply padding. If
    /// padding is to be applied then the max_len parameter may be used with
    /// any of the HASHED_CIPHERTEXT_PADDED_DATA_SIZE enumeration values.
    /// This value indicates the maximum length of the plaintext that may be
    /// encrypted. The padding scheme applies two bytes for length of padding
    /// plus padding bytes.
    ///
    /// If allow_truncation parameter is set to
    /// true then if the message parameter data is longer than
    /// max_len then it will be truncated to max_len.
    /// If the allow_truncation parameter
    /// is set to false then if the message parameter data is longer than
    /// max_len then an exception will be thrown.
    ///
    /// <param name="message">Message to hashed elgamal encrypt.</param>
    /// <param name="nonce">Randomly chosen nonce in [1,Q).</param>
    /// <param name="hashPrefix">A prefix value for the hash used to create the session key.</param>
    /// <param name="publicKey">ElGamal public key.</param>
    /// <param name="seed">Hash of the ballot description.</param>
    /// <param name="max_len">Indicates the maximum length of plaintext,
    ///                       must be one of the `HASHED_CIPHERTEXT_PADDED_DATA_SIZE`
    ///                       enumeration values.
    /// </param>
    /// <param name="allow_truncation">Truncates data to the max_len if set to true.
    /// </param>
    /// <param name="shouldUsePrecomputedValues">If true, the function will attempt
    ///                                          to use a precomputed value form the precompute buffer
    /// </param>
    /// <returns>A ciphertext triple.</returns>
    /// </summary>
    EG_API std::unique_ptr<HashedElGamalCiphertext>
    hashedElgamalEncrypt(std::vector<uint8_t> message, const ElementModQ &nonce,
                         const std::string &hashPrefix, const ElementModP &publicKey,
                         const ElementModQ &seed, HASHED_CIPHERTEXT_PADDED_DATA_SIZE max_len,
                         bool allowTruncation, bool usePrecompute = false);

    /// <summary>
    /// Encrypts a message with the Auxiliary Encryption method (as specified in the
    /// ElectionGuard specification) given a random nonce, an ElGamal public key,
    /// and an encryption seed.
    ///
    /// the `message` parameter must be a multiple of the block length (32)
    /// and the ciphertext will be the same size.
    ///
    /// <param name="message">Message to hashed elgamal encrypt.</param>
    /// <param name="nonce">Randomly chosen nonce in [1,Q).</param>
    /// <param name="hashPrefix">A prefix value for the hash used to create the session key.</param>
    /// <param name="publicKey">ElGamal public key.</param>
    /// <param name="seed">A seed value used to create the session key.</param>
    /// <param name="shouldUsePrecomputedValues">If true, the function will attempt
    ///                                          to use a precomputed value form the precompute buffer
    /// </param>
    /// <returns>A ciphertext triple.</returns>
    /// </summary>
    EG_API std::unique_ptr<HashedElGamalCiphertext>
    hashedElgamalEncrypt(std::vector<uint8_t> message, const ElementModQ &nonce,
                         const std::string &hashPrefix, const ElementModP &publicKey,
                         const ElementModQ &seed, bool usePrecompute = false);

} // namespace electionguard

#endif /* __ELECTIONGUARD__CPP_ELGAMAL_HPP_INCLUDED__ */
