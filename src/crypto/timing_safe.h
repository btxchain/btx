// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_CRYPTO_TIMING_SAFE_H
#define BTX_CRYPTO_TIMING_SAFE_H

#include <cstddef>
#include <cstdint>
#include <uint256.h>

/**
 * Constant-time comparison of two byte buffers.
 * Returns true if they are equal, false otherwise.
 * Execution time does not depend on the position of the first differing byte.
 */
[[nodiscard]] inline bool TimingSafeEqual(const unsigned char* a,
                                          const unsigned char* b,
                                          size_t len) noexcept
{
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

/**
 * Constant-time comparison of two uint256 values.
 * Unlike uint256::operator==, this does not short-circuit on the first
 * differing byte, preventing timing side-channels in proof verification.
 */
[[nodiscard]] inline bool TimingSafeEqual(const uint256& a, const uint256& b) noexcept
{
    return TimingSafeEqual(a.data(), b.data(), uint256::size());
}

#endif // BTX_CRYPTO_TIMING_SAFE_H
