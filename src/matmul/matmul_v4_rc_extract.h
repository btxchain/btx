// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_EXTRACT_H
#define BTX_MATMUL_MATMUL_V4_RC_EXTRACT_H

#include <matmul/matmul_v4_lt.h>
#include <uint256.h>

#include <cassert>
#include <cstdint>

// ENC_RC ExtractMX. P0.5: int64 Extract end-to-end (no int32 narrow).

namespace matmul::v4::rc {

inline constexpr uint32_t kRCMxBlockLen = lt::kMatExpandMxBlockLen;

inline void ExtractMXTileInt64(const uint256& prf_key, uint32_t i, uint32_t bj,
                               const int64_t raw64[kRCMxBlockLen], int8_t out[kRCMxBlockLen])
{
    assert(raw64 != nullptr && out != nullptr);
    int8_t mu_tile[kRCMxBlockLen];
    lt::ExtractMatExpandMxTileMantissas(prf_key, i, bj, raw64, mu_tile);
    const uint8_t e = lt::DeriveMatExpandMxScale(prf_key, i, bj);
    for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
        out[t] = static_cast<int8_t>(static_cast<int32_t>(mu_tile[t]) * (int32_t{1} << e));
    }
}

inline void ExtractMXMatrixInt64(const uint256& prf_key, const int64_t* Y, uint32_t rows,
                                 uint32_t cols, int8_t* out)
{
    assert(Y != nullptr && out != nullptr);
    assert(cols % kRCMxBlockLen == 0);
    const uint32_t n_blocks = cols / kRCMxBlockLen;
    for (uint32_t i = 0; i < rows; ++i) {
        for (uint32_t bj = 0; bj < n_blocks; ++bj) {
            const size_t base = static_cast<size_t>(i) * cols +
                                static_cast<size_t>(bj) * kRCMxBlockLen;
            ExtractMXTileInt64(prf_key, i, bj, Y + base, out + base);
        }
    }
}

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
