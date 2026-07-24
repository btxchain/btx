// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MATMUL_MATMUL_V4_FAST_EXACT_H
#define BITCOIN_MATMUL_MATMUL_V4_FAST_EXACT_H

#include <cstdint>
#include <vector>

namespace matmul::v4::fast_exact {

/** Miner-local one-level Strassen candidate for row-major S8 x S8 -> S32.
 *
 *  This does not define consensus.  It is an exact alternative implementation
 *  used to calibrate the fastest-known algorithm.  It succeeds only when all
 *  dimensions are non-zero/even, input sizes match, every Strassen operand
 *  sum/difference remains in signed INT8, and final entries fit signed INT32.
 *  False means the caller must use the classical exact reference.
 */
[[nodiscard]] bool GemmS8S8Strassen1(const std::vector<int8_t>& left,
                                     const std::vector<int8_t>& right,
                                     uint32_t rows, uint32_t inner, uint32_t cols,
                                     std::vector<int32_t>& out);

} // namespace matmul::v4::fast_exact

#endif // BITCOIN_MATMUL_MATMUL_V4_FAST_EXACT_H
