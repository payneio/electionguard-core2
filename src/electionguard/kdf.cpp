#include "electionguard/kdf.hpp"

#include "electionguard/hmac.hpp"

#include <cstring>
#include <stdexcept>

using std::string;
using std::vector;

namespace electionguard
{
    // Helper: encode uint32_t as 4 bytes big-endian
    static void push_be32(vector<uint8_t> &buf, uint32_t value)
    {
        buf.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        buf.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>(value & 0xFF));
    }

    // SP 800-108r1 counter-mode KDF using HMAC-SHA-256 as PRF.
    // For i = 1..numKeys:
    //   key_i = HMAC-SHA-256(secret, i_be32 || label || 0x00 || context || L_be32)
    // Where L = numKeys * 256 (output length in bits).
    vector<vector<uint8_t>> KDF::derive(const vector<uint8_t> &secret, const string &label,
                                        const vector<uint8_t> &context, uint32_t numKeys)
    {
        if (secret.size() != 32) {
            throw std::invalid_argument("KDF::derive: secret must be exactly 32 bytes");
        }

        const uint32_t L = numKeys * 256U; // output length in bits

        vector<vector<uint8_t>> keys;
        keys.reserve(numKeys);

        for (uint32_t counter = 1; counter <= numKeys; ++counter) {
            // Build the HMAC message:
            // counter_be32 || label || 0x00 || context || L_be32
            vector<uint8_t> message;
            message.reserve(4 + label.size() + 1 + context.size() + 4);

            push_be32(message, counter);

            for (auto ch : label) {
                message.push_back(static_cast<uint8_t>(ch));
            }

            message.push_back(0x00); // separator

            message.insert(message.end(), context.begin(), context.end());

            push_be32(message, L);

            // HMAC-SHA-256(secret, message) — pass length=0 so data is used as-is
            auto key_i = HMAC::compute(secret, message, 0, 0);
            keys.push_back(std::move(key_i));
        }

        return keys;
    }

} // namespace electionguard
