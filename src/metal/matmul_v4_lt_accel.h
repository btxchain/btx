// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_METAL_MATMUL_V4_LT_ACCEL_H
#define BITCOIN_METAL_MATMUL_V4_LT_ACCEL_H

#include <matmul/matmul_v4_lt.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

// Apple Metal backend for MatMul v4.4 ENC-DR-LT (MatExpand).
// Digests bit-identical to ComputeDigestBMX4CLT. s8xs8 prefers MPP TensorOps
// after ExactGemm self-qual; else MSL ALU. Never label ALU as TensorOps.
// Lever-B MX Extract + scale-partitioned B̂·V run on the host via
// WindowSketchMinerLT (no Metal Extract twin — fail-closed ExactGemm inject).

namespace matmul_v4::metal {

[[nodiscard]] bool IsMatMulLTMetalAvailable();

[[nodiscard]] bool LaunchGemmS8S8(const std::vector<int8_t>& left,
                                  const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t inner, uint32_t cols,
                                  std::vector<int32_t>& out);
[[nodiscard]] bool LaunchGemmS32S8(const std::vector<int32_t>& left,
                                   const std::vector<int8_t>& right,
                                   uint32_t rows, uint32_t inner, uint32_t cols,
                                   std::vector<int32_t>& out);

[[nodiscard]] bool ComputeDigestsOnlyLTMetal(const CBlockHeader& tmpl, uint32_t n,
                                             const uint64_t* nonces, size_t count,
                                             std::vector<matmul::v4::lt::DigestOnlyResultLT>& out);

/** True iff most recent LaunchGemmS8S8 used MPP TensorOps (not ALU). */
[[nodiscard]] bool LtLastS8S8UsedTensorOps();

} // namespace matmul_v4::metal

#endif // BITCOIN_METAL_MATMUL_V4_LT_ACCEL_H
