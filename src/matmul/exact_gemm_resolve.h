// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_EXACT_GEMM_RESOLVE_H
#define BTX_MATMUL_EXACT_GEMM_RESOLVE_H

#include <matmul/matmul_v4_lt.h>

// Thin resolve surface so pow.cpp / miners can inject device ExactGemm without
// pulling matmul_v4_lt.h into every accel_v4.h consumer.

namespace matmul_v4::accel {

/** Build an injectable ExactGemmBackend for MatExpand / LT mining. An explicit
 *  BTX_MATMUL_LT_EXACT_BACKEND=tpu|trainium selects a registered, self-qualified
 *  bounded-exact cloud provider; otherwise ResolveBackend() wires CUDA, HIP,
 *  Metal, or Ascend. Null slots keep MatExpand on CPU ExactGemm*, and false
 *  provider returns fall back per call. Winners always CPU-reseal.
 *
 *  LT-only: does NOT run ProbeRCSelfQual / clear on RC deficit. RC self-qual
 *  must never corrupt a valid LT ExactGemm inject while RC is inactive. */
[[nodiscard]] matmul::v4::lt::ExactGemmBackend MakeResolvedExactGemmBackend();

/** Same provider resolution as MakeResolvedExactGemmBackend, then RC fail-closed
 *  gate (ProbeRCSelfQual). On mining_accelerator_ok failure returns empty
 *  backend (= CPU ExactGemmS8S8). RC callers only — never use for LT mining.
 *
 *  F5: results are cached by {provider_label, gemm_fn, epoch}. Repeated calls
 *  reuse the cached backend and do NOT re-enter ProbeRCSelfQual. */
[[nodiscard]] matmul::v4::lt::ExactGemmBackend MakeResolvedExactGemmBackendForRC();

/** Apply RC self-qual gate to an already-resolved ExactGemm candidate.
 *  Cached by {provider_label, gemm_s8s8 fn ptr, epoch}. epoch=-1 is the
 *  default (non-height) probe used by miners. */
[[nodiscard]] matmul::v4::lt::ExactGemmBackend GateExactGemmWithRCSelfQualCached(
    matmul::v4::lt::ExactGemmBackend backend, const char* provider_label,
    int32_t epoch = -1);

/** Test hook: clear the F5 resolve/self-qual cache (process-local). */
void ResetRCExactGemmResolveCacheForTest();

/** Build an injectable ExactMxProjectionBackend for miner-local B̂·V.
 *  ResolveBackend() wires CUDA/HIP LaunchProjectedRightMx, Metal
 *  TryLaunchLtMetalMxProjectRight, or Ascend TryLaunchLtCubeMxProjectRight.
 *  TPU/Trainium ExactGemm providers do not expose MX; those requests leave
 *  project_right null (CPU oracle via ComputeProjectedRightMxDispatched).
 *  Mismatched device results fail closed to ComputeProjectedRightMxBlockScaleLT. */
[[nodiscard]] matmul::v4::lt::ExactMxProjectionBackend MakeResolvedExactMxProjectionBackend();

} // namespace matmul_v4::accel

#endif // BTX_MATMUL_EXACT_GEMM_RESOLVE_H
