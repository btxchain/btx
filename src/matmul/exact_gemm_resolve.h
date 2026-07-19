// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_EXACT_GEMM_RESOLVE_H
#define BTX_MATMUL_EXACT_GEMM_RESOLVE_H

#include <matmul/matmul_v4_lt.h>

// Thin resolve surface so pow.cpp / miners can inject device ExactGemm without
// pulling matmul_v4_lt.h into every accel_v4.h consumer.

namespace matmul_v4::accel {

/** Build an injectable ExactGemmBackend for MatExpand GEMMs from
 *  ResolveBackend(). Wires CUDA TryLaunchLtImma*, HIP TryLaunchLtMfma*,
 *  Metal TryLaunchLtTensorOps*, and Ascend TryLaunchLtCube* when selected.
 *  Null slots (CPU) keep MatExpand on ExactGemm*; false Try* returns also
 *  fall back per-call. Winners always CPU-reseal. */
[[nodiscard]] matmul::v4::lt::ExactGemmBackend MakeResolvedExactGemmBackend();

} // namespace matmul_v4::accel

#endif // BTX_MATMUL_EXACT_GEMM_RESOLVE_H
