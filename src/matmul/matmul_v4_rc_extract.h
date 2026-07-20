// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_EXTRACT_H
#define BTX_MATMUL_MATMUL_V4_RC_EXTRACT_H

#include <matmul/matmul_v4_lt.h>
#include <uint256.h>

#include <cassert>
#include <cstdint>
#include <limits>

// ENC_RC ExtractMX — thin wrappers over Lever-B MX Extract
// (DeriveMatExpandMxScale + ExtractMatExpandMxTileMantissas).
// Normative: doc/btx-matmul-v4.4-resident-curriculum-unified-proposal-2026-07-20.md §R.1
//
// RULES (H1/H2/H8): Y is the COMPLETED exact integer accumulator (never float /
// partial requant); exactly ONE ExtractMX per GEMM stage; output is canonical
// signed-magnitude int8 in [-48,48] (M11 has no −0).

namespace matmul::v4::rc {

inline constexpr uint32_t kRCMxBlockLen = lt::kMatExpandMxBlockLen;

/** Cast exact int64 cell → int32 for the LT Extract tile API. Stage bounds in
 *  §R.1.4 fit signed int32 (max Z≈2^30.76). */
inline int32_t ExactInt64ToExtractInt32(int64_t y)
{
    assert(y >= static_cast<int64_t>(std::numeric_limits<int32_t>::min()));
    assert(y <= static_cast<int64_t>(std::numeric_limits<int32_t>::max()));
    return static_cast<int32_t>(y);
}

/** ExtractMX over an exact int64 accumulator matrix Y (rows × cols, row-major).
 *  cols MUST be divisible by 32. out[i][j] = μ·2^e ∈ [-48,48]. */
inline void ExtractMXMatrixInt64(const uint256& prf_key, const int64_t* Y, uint32_t rows,
                                 uint32_t cols, int8_t* out)
{
    assert(Y != nullptr && out != nullptr);
    assert(cols % kRCMxBlockLen == 0);
    const uint32_t n_blocks = cols / kRCMxBlockLen;
    for (uint32_t i = 0; i < rows; ++i) {
        for (uint32_t bj = 0; bj < n_blocks; ++bj) {
            int32_t raw32[kRCMxBlockLen];
            const size_t base = static_cast<size_t>(i) * cols +
                                static_cast<size_t>(bj) * kRCMxBlockLen;
            for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
                raw32[t] = ExactInt64ToExtractInt32(Y[base + t]);
            }
            int8_t mu_tile[kRCMxBlockLen];
            lt::ExtractMatExpandMxTileMantissas(prf_key, i, bj, raw32, mu_tile);
            const uint8_t e = lt::DeriveMatExpandMxScale(prf_key, i, bj);
            for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
                out[base + t] = static_cast<int8_t>(static_cast<int32_t>(mu_tile[t]) *
                                                    (int32_t{1} << e));
            }
        }
    }
}

/** ExtractMX over an exact int32 accumulator matrix (score / fwd / bwd stages
 *  with bound < 2^24). Same tile semantics as the int64 path. */
inline void ExtractMXMatrixInt32(const uint256& prf_key, const int32_t* Y, uint32_t rows,
                                 uint32_t cols, int8_t* out)
{
    assert(Y != nullptr && out != nullptr);
    assert(cols % kRCMxBlockLen == 0);
    const uint32_t n_blocks = cols / kRCMxBlockLen;
    for (uint32_t i = 0; i < rows; ++i) {
        for (uint32_t bj = 0; bj < n_blocks; ++bj) {
            const size_t base = static_cast<size_t>(i) * cols +
                                static_cast<size_t>(bj) * kRCMxBlockLen;
            const int32_t* raw32 = Y + base;
            int8_t mu_tile[kRCMxBlockLen];
            lt::ExtractMatExpandMxTileMantissas(prf_key, i, bj, raw32, mu_tile);
            const uint8_t e = lt::DeriveMatExpandMxScale(prf_key, i, bj);
            for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
                out[base + t] = static_cast<int8_t>(static_cast<int32_t>(mu_tile[t]) *
                                                    (int32_t{1} << e));
            }
        }
    }
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_EXTRACT_H
