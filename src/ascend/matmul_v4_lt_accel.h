// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_ASCEND_MATMUL_V4_LT_ACCEL_H
#define BITCOIN_ASCEND_MATMUL_V4_LT_ACCEL_H

#include <matmul/matmul_v4_lt.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

// ---------------------------------------------------------------------------
// Huawei Ascend 950 (昇腾) ExactGemm host backend for MatMul v4.4 ENC-DR-LT.
//
// Grounded in CANN ≥ 9.1 / Ascend 950PR·DT (dav-3510) aclnn / asc-devkit notes:
//   aclnnMatmul / aclnnMm / aclnnMatmulWeightNz + INT8 via
//   aclnnCalculateMatmulWeightSize(+V2) + aclnnTransMatmulWeight.
// Two-phase GetWorkspaceSize + execute; cubeMathType KEEP_DTYPE (no HF32 /
// down-precision). `used_cube_path` is set ONLY after process-local
// ExactGemmS8S8 self-qual (odd-K + max-|entry| corners) AND a Cube/aclnn
// launch that matched byte-for-byte.
//
// Without CANN (default CI / BTX_ENABLE_ASCEND=OFF, or ON without toolkit):
// stub declines — never pretends Cube ran. Consensus remains the CPU integer
// transcript. Public activation remains inert (INT32_MAX).
// ---------------------------------------------------------------------------

namespace matmul_v4::ascend {

/** True iff this build has CANN, an NPU is visible, and process-local
 *  ExactGemmS8S8 self-qualification (incl. odd-accumulator / max-|entry|
 *  probes) passed on the Cube/aclnn path. */
[[nodiscard]] bool IsAscendExactGemmAvailable();

/** Host ExactGemmS8S8 via Ascend Cube/aclnn when available. On success `out`
 *  is byte-identical to matmul::v4::lt::ExactGemmS8S8. If `used_cube_path` is
 *  non-null it is set true ONLY when the Cube/aclnn datapath executed after
 *  self-qual; otherwise false. Returns false → caller MUST use CPU ExactGemm. */
[[nodiscard]] bool ExactGemmS8S8Ascend(const std::vector<int8_t>& left,
                                       const std::vector<int8_t>& right,
                                       uint32_t rows, uint32_t inner, uint32_t cols,
                                       std::vector<int32_t>& out,
                                       bool* used_cube_path = nullptr);

/** ExactGemmS32S8Ascend — declines until a proven exact Cube INT32×INT8 path
 *  exists; callers fall back to CPU ExactGemmS32S8. Never sets used_cube_path. */
[[nodiscard]] bool ExactGemmS32S8Ascend(const std::vector<int32_t>& left,
                                        const std::vector<int8_t>& right,
                                        uint32_t rows, uint32_t inner, uint32_t cols,
                                        std::vector<int32_t>& out,
                                        bool* used_cube_path = nullptr);

/** ExactGemmBackend::S8S8Fn / S32S8Fn adapters — require used_cube_path=true. */
[[nodiscard]] bool TryLaunchLtCubeGemmS8S8(const std::vector<int8_t>& left,
                                           const std::vector<int8_t>& right,
                                           uint32_t rows, uint32_t inner, uint32_t cols,
                                           std::vector<int32_t>& out);
[[nodiscard]] bool TryLaunchLtCubeGemmS32S8(const std::vector<int32_t>& left,
                                            const std::vector<int8_t>& right,
                                            uint32_t rows, uint32_t inner, uint32_t cols,
                                            std::vector<int32_t>& out);

/** Digest-only ENC-DR-LT entry. Declines unless IsAscendExactGemmAvailable().
 *  Injects Cube S8S8 only; S32S8 remains CPU ExactGemm. */
[[nodiscard]] bool ComputeDigestsOnlyLTAscend(
    const CBlockHeader& tmpl, uint32_t n, const uint64_t* nonces, size_t count,
    std::vector<matmul::v4::lt::DigestOnlyResultLT>& out);

} // namespace matmul_v4::ascend

#endif // BITCOIN_ASCEND_MATMUL_V4_LT_ACCEL_H
