// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_EXACT_GEMM_RESOLVE_H
#define BTX_MATMUL_EXACT_GEMM_RESOLVE_H

#include <matmul/matmul_v4_lt.h>

// Thin resolve surface so pow.cpp / miners can inject device ExactGemm without
// pulling matmul_v4_lt.h into every accel_v4.h consumer.

namespace matmul_v4::accel {

/** Build an injectable ExactGemmBackend for MatExpand GEMMs. An explicit
 *  BTX_MATMUL_LT_EXACT_BACKEND=tpu|trainium selects a registered, self-qualified
 *  bounded-exact cloud provider; otherwise ResolveBackend() wires CUDA, HIP,
 *  Metal, or Ascend. Null slots keep MatExpand on CPU ExactGemm*, and false
 *  provider returns fall back per call. Winners always CPU-reseal. */
[[nodiscard]] matmul::v4::lt::ExactGemmBackend MakeResolvedExactGemmBackend();

/** Build an injectable ExactMxProjectionBackend for miner-local B̂·V.
 *  ResolveBackend() wires CUDA/HIP LaunchProjectedRightMx, Metal
 *  TryLaunchLtMetalMxProjectRight, or Ascend TryLaunchLtCubeMxProjectRight.
 *  TPU/Trainium ExactGemm providers do not expose MX; those requests leave
 *  project_right null (CPU oracle via ComputeProjectedRightMxDispatched).
 *  Mismatched device results fail closed to ComputeProjectedRightMxBlockScaleLT. */
[[nodiscard]] matmul::v4::lt::ExactMxProjectionBackend MakeResolvedExactMxProjectionBackend();

} // namespace matmul_v4::accel

#endif // BTX_MATMUL_EXACT_GEMM_RESOLVE_H
