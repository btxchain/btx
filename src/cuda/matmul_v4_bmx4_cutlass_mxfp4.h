// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_BMX4_CUTLASS_MXFP4_H
#define BITCOIN_CUDA_MATMUL_V4_BMX4_CUTLASS_MXFP4_H

#include <cstdint>
#include <string>

// Scale-partitioned grouped MXFP4 projection lane (B200 / Blackwell).
//
// Design: doc/btx-matmul-v4.4-exact-accel-lanes.md §2.
// CPU reference: matmul::v4::bmx4::ComputeProjected{Left,Right}ScalePartitionedBMX4C.
//
// cuBLAS 13.x serves NVFP4 (UE4M3/16) but not OCP MXFP4 (E2M1 + E8M0/32).
// CUTLASS exposes the latter on Blackwell. This header is the pinned integration
// surface: a real CUTLASS persistent grouped GEMM replaces the stub when the
// toolkit + silicon are present. Until then the backend keeps the INT8 tier
// (and the existing unit-scale mxf4 path) and stays fail-closed.
//
// Contract (exactness):
//   * No fast accumulation, stochastic rounding, TF32, or approximate scales.
//   * Reject NaN / Inf / fractional outputs / analytic-bound violations.
//   * Qualification binds GPU, firmware, driver, toolkit, compiler, binary /
//     kernel hash, algorithm, dimensions, Q, chunking, and math flags.
//   * Every mantissa product <= 36; every bucket accumulation <= 36n < 2^21,
//     so a proven 24-bit FP32 accumulator is exact.
//   * Apply 2^e in the exact integer epilogue; do not reorient committed scales.
//
// Grouped problem shape for one 32-row (or 32-col) block:
//   for e in {0,1,2,3}:
//     K_e = |{ j : committed_scale(block, j) = e }|
//     partial_e = Left_block * Right_bucket_e   (K = K_e)
//   Out_block += sum_e (partial_e << e)
// Total K across the four buckets equals n, not 4n.

namespace matmul_v4::cuda::cutlass_mxfp4 {

struct GroupedMxfp4Problem {
    uint32_t M{0};
    uint32_t N{0};
    uint32_t K_e[4]{0, 0, 0, 0}; // partition of K; sum == K_total
    uint32_t K_total{0};
};

/** True when a pinned CUTLASS MXFP4 grouped kernel is linked and the device
 *  has passed M-t24 + scale-partitioned qualification. Default builds return
 *  false (inert). */
[[nodiscard]] inline bool IsGroupedMxfp4Available()
{
#if defined(BTX_BMX4C_CUTLASS_MXFP4)
    return true; // real bring-up flips this behind a runtime qualification gate
#else
    return false;
#endif
}

/** Launch the scale-partitioned grouped MXFP4 projection for one problem.
 *  Returns false and sets `error` when CUTLASS is unavailable or any safety
 *  gate fails — caller MUST fall back to the INT8 / CPU reference. */
[[nodiscard]] inline bool LaunchGroupedMxfp4Projection(const GroupedMxfp4Problem& /*problem*/,
                                                       std::string& error)
{
    error = "CUTLASS scale-partitioned MXFP4 projection is a pinned integration "
            "point (enable BTX_BMX4C_CUTLASS_MXFP4 on qualified Blackwell + CUTLASS; "
            "see doc/btx-matmul-v4.4-exact-accel-lanes.md)";
    return false;
}

} // namespace matmul_v4::cuda::cutlass_mxfp4

#endif // BITCOIN_CUDA_MATMUL_V4_BMX4_CUTLASS_MXFP4_H
