#include "electionguard/hash.hpp"

#include "../../libs/hacl/Hacl_Bignum256.hpp"
#include "../../libs/hacl/Hacl_Streaming_SHA2.hpp"
#include "electionguard/hmac.hpp"
#include "log.hpp"

#include <cstring>
#include <iomanip>
#include <iostream>

using hacl::Bignum256;
using hacl::StreamingSHA2;
using hacl::StreamingSHA2Mode;
using std::get;
using std::make_unique;
using std::move;
using std::nullptr_t;
using std::out_of_range;
using std::reference_wrapper;
using std::string;
using std::to_string;
using std::unique_ptr;
using std::vector;

namespace electionguard
{
    string get_hash_string(CryptoHashableType a);
    template <typename T> string hash_inner_vector(vector<T> inner_vector);
    void push_hash_update(StreamingSHA2 *p, CryptoHashableType a);
    unique_ptr<StreamingSHA2> hash_open();
    unique_ptr<ElementModQ> hash_close(StreamingSHA2 *p);

    enum CryptoHashableTypeEnum {
        NULL_PTR = 0,
        CRYPTOHASHABLE_PTR = 1,
        ELEMENTMODP_PTR = 2,
        ELEMENTMODQ_PTR = 3,
        CRYPTOHASHABLE_REF = 4,
        ELEMENTMODP_REF = 5,
        ELEMENTMODQ_REF = 6,
        CRYPTOHASHABLE_CONST_REF = 7,
        ELEMENTMODP_CONST_REF = 8,
        ELEMENTMODQ_CONST_REF = 9,
        UINT64_T = 10,
        STRING = 11,
        VECTOR_CRYPTOHASHABLE_PTR = 12,
        VECTOR_ELEMENTMODP_PTR = 13,
        VECTOR_ELEMENTMODQ_PTR = 14,
        VECTOR_CRYPTOHASHABLE_REF = 15,
        VECTOR_ELEMENTMODP_REF = 16,
        VECTOR_ELEMENTMODQ_REF = 17,
        VECTOR_CRYPTOHASHABLE_CONST_REF = 18,
        VECTOR_ELEMENTMODP_CONST_REF = 19,
        VECTOR_ELEMENTMODQ_CONST_REF = 20,
        VECTOR_UINT64_T = 21,
        VECTOR_STRING = 22,
        VECTOR_UINT8_T = 23
    };

    const char delimiter_char = '|';
    const string null_string = "null";

    uint8_t delimiter[1] = {delimiter_char};

    unique_ptr<ElementModQ> hash_elems(const vector<CryptoHashableType> &a)
    {
        uint8_t output[MAX_Q_SIZE] = {};
        unique_ptr<StreamingSHA2> p = hash_open();

        if (a.empty()) {
            push_hash_update(p.get(), nullptr);
        } else {
            for (const CryptoHashableType &item : a) {
                push_hash_update(p.get(), item);
            }
        }
        return hash_close(p.get());
    }

    unique_ptr<ElementModQ> hash_elems(CryptoHashableType a)
    {
        unique_ptr<StreamingSHA2> p = hash_open();
        push_hash_update(p.get(), a);
        return hash_close(p.get());
    }

    unique_ptr<StreamingSHA2> hash_open()
    {
        auto p = make_unique<StreamingSHA2>(StreamingSHA2Mode::SHA2_256);
        p->update(static_cast<uint8_t *>(delimiter), sizeof(delimiter));
        return move(p);
    }

    unique_ptr<ElementModQ> hash_close(StreamingSHA2 *p)
    {
        uint8_t output[MAX_Q_SIZE] = {};
        p->finish(static_cast<uint8_t *>(output));

        auto *bigNum = Bignum256::fromBytes(sizeof(output), static_cast<uint8_t *>(output));
        if (bigNum == nullptr) {
            throw out_of_range("bytes_to_p could not allocate");
        }

        // The ElementModQ constructor expects the bignum
        // to be a certain size, but there's no guarantee
        // that constraint is satisfied by new_bn_from_bytes_be
        // so copy it into a new element that is the correct size
        // and free the allocated resources
        uint64_t normalized[MAX_Q_LEN] = {};
        memcpy(static_cast<uint64_t *>(normalized), bigNum, sizeof(output));
        free(bigNum);

        auto element = make_unique<ElementModQ>(normalized, true);

        // TODO: take the result mod Q - 1
        // to produce a result that is [0,q-1]
        return add_mod_q(*element, ZERO_MOD_Q());
    }

    template <typename T> string hash_inner_vector(vector<T> inner_vector)
    {
        if (inner_vector.empty()) {
            return null_string;
        }
        vector<CryptoHashableType> hashable_vector(inner_vector.begin(), inner_vector.end());
        return hash_elems(hashable_vector)->toHex();
    }

    string get_hash_string(CryptoHashableType a)
    {
        switch (a.index()) {
            case NULL_PTR: // nullptr_t
            {
                return null_string;
            }
            case CRYPTOHASHABLE_PTR: // CryptoHashable *
            {
                auto hashable = get<CryptoHashable *>(a)->crypto_hash();
                return hashable->toHex();
            }
            case ELEMENTMODP_PTR: // ElementModP *
            {
                return get<ElementModP *>(a)->toHex();
            }
            case ELEMENTMODQ_PTR: // ElementModQ *
            {
                return get<ElementModQ *>(a)->toHex();
            }
            case CRYPTOHASHABLE_REF: // reference_wrapper<CryptoHashable>
            {
                auto hashable = get<reference_wrapper<CryptoHashable>>(a).get().crypto_hash();
                return hashable->toHex();
                //Log::debug("input string: " + input_string);
            }
            case ELEMENTMODP_REF: // reference_wrapper<ElementModP>
            {
                return get<reference_wrapper<ElementModP>>(a).get().toHex();
            }
            case ELEMENTMODQ_REF: // reference_wrapper<ElementModQ>
            {
                return get<reference_wrapper<ElementModQ>>(a).get().toHex();
            }
            case CRYPTOHASHABLE_CONST_REF: // reference_wrapper<const CryptoHashable>
            {
                auto hashable = get<reference_wrapper<const CryptoHashable>>(a).get().crypto_hash();
                return hashable->toHex();
            }
            case ELEMENTMODP_CONST_REF: // reference_wrapper<const ElementModP>
            {
                return get<reference_wrapper<const ElementModP>>(a).get().toHex();
            }
            case ELEMENTMODQ_CONST_REF: // reference_wrapper<const ElementModQ>
            {
                return get<reference_wrapper<const ElementModQ>>(a).get().toHex();
            }
            case UINT64_T: // uint64_t
            {
                uint64_t i = get<uint64_t>(a);
                if (i != 0) {
                    return to_string(i);
                }
                return null_string;
            }
            case STRING: // string
            {
                auto hashable = get<string>(a);
                if (hashable.empty()) {
                    return null_string;
                }
                return hashable;
            }
            case VECTOR_CRYPTOHASHABLE_PTR: // vector<CryptoHashable *>
            {
                return hash_inner_vector<CryptoHashable *>(get<vector<CryptoHashable *>>(a));
            }
            case VECTOR_ELEMENTMODP_PTR: // vector<ElementModP *>
            {
                return hash_inner_vector<ElementModP *>(get<vector<ElementModP *>>(a));
            }
            case VECTOR_ELEMENTMODQ_PTR: // vector<ElementModQ *>
            {
                return hash_inner_vector<ElementModQ *>(get<vector<ElementModQ *>>(a));
            }
            case VECTOR_CRYPTOHASHABLE_REF: // vector<reference_wrapper<CryptoHashable>>
            {
                return hash_inner_vector<reference_wrapper<CryptoHashable>>(
                  get<vector<reference_wrapper<CryptoHashable>>>(a));
            }
            case VECTOR_ELEMENTMODP_REF: // vector<reference_wrapper<ElementModP>>
            {
                return hash_inner_vector<reference_wrapper<ElementModP>>(
                  get<vector<reference_wrapper<ElementModP>>>(a));
            }
            case VECTOR_ELEMENTMODQ_REF: // vector<reference_wrapper<ElementModQ>>
            {
                return hash_inner_vector<reference_wrapper<ElementModQ>>(
                  get<vector<reference_wrapper<ElementModQ>>>(a));
            }
            case VECTOR_CRYPTOHASHABLE_CONST_REF: // vector<reference_wrapper<const CryptoHashable>>
            {
                return hash_inner_vector<reference_wrapper<const CryptoHashable>>(
                  get<vector<reference_wrapper<const CryptoHashable>>>(a));
            }
            case VECTOR_ELEMENTMODP_CONST_REF: // vector<reference_wrapper<const ElementModP>>
            {
                return hash_inner_vector<reference_wrapper<const ElementModP>>(
                  get<vector<reference_wrapper<const ElementModP>>>(a));
            }
            case VECTOR_ELEMENTMODQ_CONST_REF: // vector<reference_wrapper<const ElementModQ>>
            {
                return hash_inner_vector<reference_wrapper<const ElementModQ>>(
                  get<vector<reference_wrapper<const ElementModQ>>>(a));
            }
            case VECTOR_UINT64_T: // vector<uint64_t>
            {
                return hash_inner_vector<uint64_t>(get<vector<uint64_t>>(a));
            }
            case VECTOR_STRING: // vector<string>
            {
                return hash_inner_vector<string>(get<vector<string>>(a));
            }
            case VECTOR_UINT8_T: // vector<string>
            {
                vector<uint8_t> temp = get<vector<uint8_t>>(a);
                return vector_uint8_t_to_hex(temp);
            }
        }

        return null_string;
    }

    void push_hash_update(StreamingSHA2 *p, CryptoHashableType a)
    {
        string input_string = get_hash_string(a);
        const auto *input = reinterpret_cast<const uint8_t *>(input_string.c_str());
        p->update(const_cast<uint8_t *>(input), input_string.size());
        p->update(static_cast<uint8_t *>(delimiter), sizeof(delimiter));
    }

    // ─────────────────────── v2.1 HMAC-SHA-256 implementation ──────────────────

    /// Pad `bytes` with leading zero bytes so the total length is `targetLen`.
    /// If `bytes.size() >= targetLen` nothing is done.
    static void pad_leading_zeros(vector<uint8_t> &bytes, size_t targetLen)
    {
        if (bytes.size() < targetLen) {
            bytes.insert(bytes.begin(), targetLen - bytes.size(), 0x00);
        }
    }

    /// Append the v2.1 binary serialisation of a single CryptoHashableType
    /// argument to `buf`.
    static void serialize_arg(vector<uint8_t> &buf, CryptoHashableType a)
    {
        switch (a.index()) {
            case NULL_PTR: // nullptr_t → skip (zero contribution)
                break;

            case CRYPTOHASHABLE_PTR: // CryptoHashable* → hash it, then emit 32 bytes
            {
                auto hashed = get<CryptoHashable *>(a)->crypto_hash();
                auto bytes = hashed->toBytes();
                pad_leading_zeros(bytes, MAX_Q_SIZE);
                buf.insert(buf.end(), bytes.begin(), bytes.end());
                break;
            }

            case ELEMENTMODP_PTR: // ElementModP* → 512 bytes big-endian
            {
                auto bytes = get<ElementModP *>(a)->toBytes();
                pad_leading_zeros(bytes, MAX_P_SIZE);
                buf.insert(buf.end(), bytes.begin(), bytes.end());
                break;
            }

            case ELEMENTMODQ_PTR: // ElementModQ* → 32 bytes big-endian
            {
                auto bytes = get<ElementModQ *>(a)->toBytes();
                pad_leading_zeros(bytes, MAX_Q_SIZE);
                buf.insert(buf.end(), bytes.begin(), bytes.end());
                break;
            }

            case CRYPTOHASHABLE_REF: {
                auto hashed = get<reference_wrapper<CryptoHashable>>(a).get().crypto_hash();
                auto bytes = hashed->toBytes();
                pad_leading_zeros(bytes, MAX_Q_SIZE);
                buf.insert(buf.end(), bytes.begin(), bytes.end());
                break;
            }

            case ELEMENTMODP_REF: {
                auto bytes = get<reference_wrapper<ElementModP>>(a).get().toBytes();
                pad_leading_zeros(bytes, MAX_P_SIZE);
                buf.insert(buf.end(), bytes.begin(), bytes.end());
                break;
            }

            case ELEMENTMODQ_REF: {
                auto bytes = get<reference_wrapper<ElementModQ>>(a).get().toBytes();
                pad_leading_zeros(bytes, MAX_Q_SIZE);
                buf.insert(buf.end(), bytes.begin(), bytes.end());
                break;
            }

            case CRYPTOHASHABLE_CONST_REF: {
                auto hashed =
                  get<reference_wrapper<const CryptoHashable>>(a).get().crypto_hash();
                auto bytes = hashed->toBytes();
                pad_leading_zeros(bytes, MAX_Q_SIZE);
                buf.insert(buf.end(), bytes.begin(), bytes.end());
                break;
            }

            case ELEMENTMODP_CONST_REF: {
                auto bytes = get<reference_wrapper<const ElementModP>>(a).get().toBytes();
                pad_leading_zeros(bytes, MAX_P_SIZE);
                buf.insert(buf.end(), bytes.begin(), bytes.end());
                break;
            }

            case ELEMENTMODQ_CONST_REF: {
                auto bytes = get<reference_wrapper<const ElementModQ>>(a).get().toBytes();
                pad_leading_zeros(bytes, MAX_Q_SIZE);
                buf.insert(buf.end(), bytes.begin(), bytes.end());
                break;
            }

            case UINT64_T: // uint64_t → 4 bytes big-endian (low 32 bits)
            {
                auto val = static_cast<uint32_t>(get<uint64_t>(a));
                buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
                buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
                buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
                buf.push_back(static_cast<uint8_t>(val & 0xFF));
                break;
            }

            case STRING: // string → raw UTF-8 bytes
            {
                const auto &s = get<string>(a);
                buf.insert(buf.end(), s.begin(), s.end());
                break;
            }

            case VECTOR_CRYPTOHASHABLE_PTR: {
                for (auto *elem : get<vector<CryptoHashable *>>(a)) {
                    auto hashed = elem->crypto_hash();
                    auto bytes = hashed->toBytes();
                    pad_leading_zeros(bytes, MAX_Q_SIZE);
                    buf.insert(buf.end(), bytes.begin(), bytes.end());
                }
                break;
            }

            case VECTOR_ELEMENTMODP_PTR: {
                for (auto *elem : get<vector<ElementModP *>>(a)) {
                    auto bytes = elem->toBytes();
                    pad_leading_zeros(bytes, MAX_P_SIZE);
                    buf.insert(buf.end(), bytes.begin(), bytes.end());
                }
                break;
            }

            case VECTOR_ELEMENTMODQ_PTR: {
                for (auto *elem : get<vector<ElementModQ *>>(a)) {
                    auto bytes = elem->toBytes();
                    pad_leading_zeros(bytes, MAX_Q_SIZE);
                    buf.insert(buf.end(), bytes.begin(), bytes.end());
                }
                break;
            }

            case VECTOR_ELEMENTMODP_REF: {
                for (const auto &ref : get<vector<reference_wrapper<ElementModP>>>(a)) {
                    auto bytes = ref.get().toBytes();
                    pad_leading_zeros(bytes, MAX_P_SIZE);
                    buf.insert(buf.end(), bytes.begin(), bytes.end());
                }
                break;
            }

            case VECTOR_ELEMENTMODQ_REF: {
                for (const auto &ref : get<vector<reference_wrapper<ElementModQ>>>(a)) {
                    auto bytes = ref.get().toBytes();
                    pad_leading_zeros(bytes, MAX_Q_SIZE);
                    buf.insert(buf.end(), bytes.begin(), bytes.end());
                }
                break;
            }

            case VECTOR_ELEMENTMODP_CONST_REF: {
                for (const auto &ref :
                     get<vector<reference_wrapper<const ElementModP>>>(a)) {
                    auto bytes = ref.get().toBytes();
                    pad_leading_zeros(bytes, MAX_P_SIZE);
                    buf.insert(buf.end(), bytes.begin(), bytes.end());
                }
                break;
            }

            case VECTOR_ELEMENTMODQ_CONST_REF: {
                for (const auto &ref :
                     get<vector<reference_wrapper<const ElementModQ>>>(a)) {
                    auto bytes = ref.get().toBytes();
                    pad_leading_zeros(bytes, MAX_Q_SIZE);
                    buf.insert(buf.end(), bytes.begin(), bytes.end());
                }
                break;
            }

            case VECTOR_UINT8_T: // vector<uint8_t> → raw bytes
            {
                const auto &bytes = get<vector<uint8_t>>(a);
                buf.insert(buf.end(), bytes.begin(), bytes.end());
                break;
            }

            default:
                // Remaining types (VECTOR_CRYPTOHASHABLE_REF, VECTOR_CRYPTOHASHABLE_CONST_REF,
                // VECTOR_UINT64_T, VECTOR_STRING) — not serialised in v2.1 binary mode.
                break;
        }
    }

    // ── Public v2.1 API ──────────────────────────────────────────────────────

    unique_ptr<ElementModQ> hash_elems_v21(const uint8_t keyBytes[32],
                                            uint8_t domainSeparator,
                                            const vector<CryptoHashableType> &args)
    {
        // Build B_1: domainSeparator || serialise(arg0) || serialise(arg1) || ...
        vector<uint8_t> data;
        data.push_back(domainSeparator);
        for (const auto &arg : args) {
            serialize_arg(data, arg);
        }

        // B_0 (HMAC key) as a vector
        vector<uint8_t> key(keyBytes, keyBytes + 32);

        // HMAC-SHA-256(key, data) — pass length=0 so HMAC::compute uses data as-is
        auto hmac = HMAC::compute(key, data, 0, 0);

        // Wrap raw 32-byte result in an unchecked ElementModQ (may be >= Q)
        return bytes_to_q(hmac, true);
    }

    unique_ptr<ElementModQ> hash_elems_v21(const ElementModQ *key,
                                            uint8_t domainSeparator,
                                            const vector<CryptoHashableType> &args)
    {
        // Extract exactly 32 bytes from the key (big-endian, left-padded with zeros)
        auto keyBytes = key->toBytes();
        pad_leading_zeros(keyBytes, MAX_Q_SIZE);

        uint8_t keyArray[32];
        memcpy(keyArray, keyBytes.data(), MAX_Q_SIZE);

        return hash_elems_v21(keyArray, domainSeparator, args);
    }

    unique_ptr<ElementModQ> hash_elems_v21_q(const ElementModQ *key,
                                              uint8_t domainSeparator,
                                              const vector<CryptoHashableType> &args)
    {
        auto result = hash_elems_v21(key, domainSeparator, args);
        // Reduce mod q: add 0 is the canonical way to invoke the modular reduction
        return add_mod_q(*result, ZERO_MOD_Q());
    }

} // namespace electionguard
