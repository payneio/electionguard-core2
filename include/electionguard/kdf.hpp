#ifndef __ELECTIONGUARD_CPP_KDF_HPP_INCLUDED__
#define __ELECTIONGUARD_CPP_KDF_HPP_INCLUDED__

#include "export.h"
#include <cstdint>
#include <string>
#include <vector>

namespace electionguard
{
    /// <summary>
    /// SP 800-108r1 counter-mode KDF using HMAC-SHA-256 as PRF.
    /// Derives `numKeys` 32-byte keys from a secret.
    /// </summary>
    class EG_API KDF
    {
      public:
        /// <summary>
        /// Derive numKeys 32-byte keys from a secret.
        ///
        /// For i = 1..numKeys:
        ///   key_i = HMAC-SHA-256(secret, i_be32 || label || 0x00 || context || L_be32)
        /// Where L = numKeys * 256 (output length in bits).
        /// </summary>
        /// <param name="secret">32-byte input key material</param>
        /// <param name="label">ASCII label string</param>
        /// <param name="context">Context bytes</param>
        /// <param name="numKeys">Number of 32-byte keys to derive</param>
        static std::vector<std::vector<uint8_t>>
        derive(const std::vector<uint8_t> &secret, const std::string &label,
               const std::vector<uint8_t> &context, uint32_t numKeys);
    };
} // namespace electionguard

#endif /* __ELECTIONGUARD_CPP_KDF_HPP_INCLUDED__ */
