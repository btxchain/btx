// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_BMX4_CUTLASS_MXFP4_H
#define BITCOIN_CUDA_MATMUL_V4_BMX4_CUTLASS_MXFP4_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Contraction-aligned MXFP4 projection lane (B200 / Blackwell).
//
// Design: doc/btx-matmul-v4.4-exact-accel-lanes.md §2.
// CPU reference: matmul::v4::bmx4::ComputeProjected{Left,Right}ScalePartitionedBMX4C.
//
// TWO datapaths, ONE exact result (the committed OCP-MX E2M1/E8M0 object is
// vendor-neutral: every path below produces byte-identical int32 output):
//
//   (1) PORTABLE EXACT (this header, ALWAYS compiled/available): a complete
//       integer MX-block projection. Each committed E8M0 code applies to one
//       32-element run of the GEMM contraction axis. The block's integer dot
//       product is therefore accumulated first and multiplied by the exact
//       power-of-two scale once. Pure integer arithmetic, no rounding, no
//       float. This is the "used when CUTLASS is unavailable" path required by
//       the exact-lane contract, and it is what the portable tier runs today.
//
//   (2) CUTLASS TENSOR KERNEL (hardware-gated, BTX_BMX4C_CUTLASS_MXFP4): a real
//       persistent block-scaled GEMM on qualified Blackwell (tcgen05 mxf4). It
//       replaces path (1) ONLY after the toolkit + silicon are present AND the
//       device passes M-t24 + scale-partitioned qualification. Stock cuBLAS
//       exposes a block-16 UE4M3/NVFP4 scale layout rather than OCP block-32
//       E8M0. Duplicating each exact power-of-two scale into two K16 slots may
//       be an exact embedding, but that packing is not implemented or
//       qualified here. CUTLASS is the direct OCP route; until a real kernel
//       is linked and qualified, IsGroupedMxfp4TensorKernelLinked() is false
//       and callers transparently use path (1).
//
// PTX / arch split (PR #89 silicon comments — keep builds honest):
//   * sm_120 / sm_120a (consumer Blackwell, RTX 5090): hand PTX `mxf4` /
//     mma.sync.mxf8f6f4 recipes target consumer ISA; may assemble only under
//     sm_120a.
//   * sm_100 / sm_100a (datacenter Blackwell, B200): rejects consumer mxf4 PTX;
//     needs a separate sm_100a-qualified CUTLASS/tcgen05 recipe.
//   * cuBLASLt mxf4: on current toolkits sm_100 and sm_120 report **no
//     algorithm** — fail closed for tensor advertising (used_tensor_path stays
//     false); portable exact path (1) remains the exact fallback. Hand-written
//     scalar decode is optional and MUST NOT set used_tensor_path.
//
// Contract (exactness), enforced by construction in path (1) and by
// qualification for path (2):
//   * No fast accumulation, stochastic rounding, TF32, or approximate scales.
//   * Reject NaN / Inf / fractional outputs / analytic-bound violations.
//   * Qualification binds GPU, firmware, driver, toolkit, compiler, binary /
//     kernel hash, algorithm, dimensions, Q, chunking, and math flags.
//   * Every mantissa product <= 36; each 32-wide block sum is <= 1152 and the
//     full output is <= 36n < 2^21, so a proven 24-bit FP32 accumulator is
//     exact (path (2)); path (1) accumulates in int32, exact for the full
//     committed magnitude window.
//   * Apply 2^e in the exact integer epilogue; do not reorient committed scales.
//
// The legacy GroupedMxfp4* API names are retained for source compatibility.
// The corrected consensus layout no longer needs a reduced-K bucket grouping:
// every scale slot already describes exactly one native 32-element K block.

namespace matmul_v4::cuda::cutlass_mxfp4 {

// OCP-MX committed-scale constants (mirror matmul::v4::bmx4::kBlockLen /
// kNumScaleCodes; duplicated here so this header stays dependency-light and
// usable from any translation unit, CUDA or portable C++).
inline constexpr uint32_t kBlockLen = 32;      // OCP block length L
inline constexpr uint32_t kNumScaleCodes = 4;  // committed E8M0 codes e in {0..3}

// Which committed operand a projection contracts. Left = P = U * Ahat, where
// A's scales are [K-block][output-column]. Right = Q = Bhat * V, where B's
// scales are [output-row][K-block].
enum class GroupedMxfp4Orientation : uint8_t {
    Left = 0,   // P[a][k] = sum_i U[a][i] * mu_a[i][k] * 2^{e_a(i/32, k)}
    Right = 1,  // Q[k][c] = sum_j mu_b[k][j] * 2^{e_b(k, j/32)} * V[j][c]
};

// Per-call telemetry. K_e counts committed K-block slots carrying exponent e;
// K_total is the number of slots, n * (n / kBlockLen). Field names are kept for
// compatibility with the pre-axis-correction reviewer API.
struct GroupedMxfp4Problem {
    uint32_t M{0};
    uint32_t N{0};
    uint64_t K_e[kNumScaleCodes]{0, 0, 0, 0}; // count of scale slots by exponent
    uint64_t K_total{0};                       // number of committed K-block slots
};

/** The portable exact scale-partitioned MXFP4 projection is ALWAYS available:
 *  it is a complete integer implementation compiled into every build. This is
 *  the "used when CUTLASS is unavailable" path — never a stub. */
[[nodiscard]] inline bool IsGroupedMxfp4Available()
{
    return true;
}

/** True only when a real CUTLASS MXFP4 grouped TENSOR kernel translation unit
 *  is compiled (CMake `BTX_BMX4C_CUTLASS_MXFP4=ON` + CUTLASS headers) AND the
 *  process-local M-t24 / scale-partitioned self-qualification has passed.
 *  Default builds link a stub that returns false — callers must use the
 *  portable exact path. Never returns true merely because a CMake flag is set. */
[[nodiscard]] bool IsGroupedMxfp4TensorKernelLinked();

/** True when the CUTLASS tensor TU was compiled into this binary (headers
 *  present). Does NOT imply it is trusted — see IsGroupedMxfp4TensorKernelLinked.
 *  Useful for tests distinguishing "option wired" vs "silicon-qualified". */
[[nodiscard]] bool IsGroupedMxfp4TensorKernelCompiled();

// ---------------------------------------------------------------------------
// Portable exact MXFP4-shaped LEFT projection.
//   P[a][k] = sum_i U[a][i] * mu_a[i][k] * 2^{e_a(i/32, k)}   (m x n row-major)
// For each output column k, every 32-row contraction block ib has one scale
// e_a(ib,k). Accumulate that block's integer dot and fold it with 2^e.
// Byte-identical to matmul::v4::bmx4::ComputeProjectedLeftScalePartitionedBMX4C
// and hence to the dense dequantized GEMM ComputeProjectedLeft.
// ---------------------------------------------------------------------------
[[nodiscard]] inline bool GroupedMxfp4ProjectLeft(const int8_t* U,
                                                  const int8_t* mu_a,
                                                  const uint8_t* scale_a,
                                                  uint32_t n,
                                                  uint32_t m,
                                                  std::vector<int32_t>& P_out,
                                                  GroupedMxfp4Problem* shape,
                                                  std::string& error)
{
    if (U == nullptr || mu_a == nullptr || scale_a == nullptr) {
        error = "GroupedMxfp4ProjectLeft: null operand";
        return false;
    }
    if (n == 0 || m == 0 || (n % kBlockLen) != 0) {
        error = "GroupedMxfp4ProjectLeft: n must be a positive multiple of 32";
        return false;
    }

    const uint32_t nblk = n / kBlockLen;
    P_out.assign(static_cast<size_t>(m) * n, 0);
    if (shape != nullptr) {
        *shape = GroupedMxfp4Problem{};
        shape->M = m;
        shape->N = n;
    }

    for (uint32_t ib = 0; ib < nblk; ++ib) {
        for (uint32_t k = 0; k < n; ++k) {
            const uint8_t e = scale_a[static_cast<size_t>(ib) * n + k];
            if (e >= kNumScaleCodes) {
                error = "GroupedMxfp4ProjectLeft: scale code out of range";
                return false;
            }
            if (shape != nullptr) {
                ++shape->K_e[e];
                ++shape->K_total;
            }
        }
    }

    for (uint32_t a = 0; a < m; ++a) {
        for (uint32_t k = 0; k < n; ++k) {
            int32_t out = 0;
            for (uint32_t ib = 0; ib < nblk; ++ib) {
                int32_t acc = 0;
                const uint32_t i0 = ib * kBlockLen;
                for (uint32_t r = 0; r < kBlockLen; ++r) {
                    const uint32_t i = i0 + r;
                    acc += static_cast<int32_t>(U[static_cast<size_t>(a) * n + i]) *
                           static_cast<int32_t>(mu_a[static_cast<size_t>(i) * n + k]);
                }
                const uint8_t e = scale_a[static_cast<size_t>(ib) * n + k];
                // Multiplication, rather than a signed left shift, is defined
                // for negative acc and is exact for e in {0,1,2,3}.
                out += acc * (1 << e);
            }
            P_out[static_cast<size_t>(a) * n + k] = out;
        }
    }
    error.clear();
    return true;
}

// ---------------------------------------------------------------------------
// Portable exact MXFP4-shaped RIGHT projection.
//   Q[k][c] = sum_j mu_b[k][j] * 2^{e_b(k, j/32)} * V[j][c]   (n x m row-major)
// For each output row k, every 32-column contraction block jb has one scale
// e_b(k,jb). Accumulate that block's integer dot and fold it with 2^e.
// ---------------------------------------------------------------------------
[[nodiscard]] inline bool GroupedMxfp4ProjectRight(const int8_t* mu_b,
                                                   const uint8_t* scale_b,
                                                   const int8_t* V,
                                                   uint32_t n,
                                                   uint32_t m,
                                                   std::vector<int32_t>& Q_out,
                                                   GroupedMxfp4Problem* shape,
                                                   std::string& error)
{
    if (mu_b == nullptr || scale_b == nullptr || V == nullptr) {
        error = "GroupedMxfp4ProjectRight: null operand";
        return false;
    }
    if (n == 0 || m == 0 || (n % kBlockLen) != 0) {
        error = "GroupedMxfp4ProjectRight: n must be a positive multiple of 32";
        return false;
    }

    const uint32_t nblk = n / kBlockLen;
    Q_out.assign(static_cast<size_t>(n) * m, 0);
    if (shape != nullptr) {
        *shape = GroupedMxfp4Problem{};
        shape->M = n;
        shape->N = m;
    }

    for (uint32_t k = 0; k < n; ++k) {
        const size_t srow = static_cast<size_t>(k) * nblk;
        for (uint32_t jb = 0; jb < nblk; ++jb) {
            const uint8_t e = scale_b[srow + jb];
            if (e >= kNumScaleCodes) {
                error = "GroupedMxfp4ProjectRight: scale code out of range";
                return false;
            }
            if (shape != nullptr) {
                ++shape->K_e[e];
                ++shape->K_total;
            }
        }
    }

    for (uint32_t k = 0; k < n; ++k) {
        const size_t srow = static_cast<size_t>(k) * nblk;
        for (uint32_t c = 0; c < m; ++c) {
            int32_t out = 0;
            for (uint32_t jb = 0; jb < nblk; ++jb) {
                const uint32_t j0 = jb * kBlockLen;
                int32_t acc = 0;
                for (uint32_t r = 0; r < kBlockLen; ++r) {
                    const uint32_t j = j0 + r;
                    acc += static_cast<int32_t>(mu_b[static_cast<size_t>(k) * n + j]) *
                           static_cast<int32_t>(V[static_cast<size_t>(j) * m + c]);
                }
                const uint8_t e = scale_b[srow + jb];
                out += acc * (1 << e);
            }
            Q_out[static_cast<size_t>(k) * m + c] = out;
        }
    }
    error.clear();
    return true;
}

/** Launch the contraction-aligned MXFP4-shaped projection for one operand.
 *  Dispatches to the CUTLASS tensor kernel when it is linked AND qualified
 *  (path (2)); otherwise runs the complete portable exact integer path (1).
 *  Fills `shape` scale-slot telemetry when non-null. Returns false and
 *  sets `error` on invalid input; never a "pending"/no-op stub. */
[[nodiscard]] inline bool LaunchGroupedMxfp4Projection(GroupedMxfp4Orientation orient,
                                                       const int8_t* proj,
                                                       const int8_t* mantissa,
                                                       const uint8_t* scale,
                                                       uint32_t n,
                                                       uint32_t m,
                                                       std::vector<int32_t>& out,
                                                       GroupedMxfp4Problem* shape,
                                                       std::string& error)
{
    // The CUTLASS tensor kernel (path (2)) is selected only when linked and,
    // on real silicon, after runtime qualification. That dispatch lives in the
    // CUDA translation unit (matmul_v4_bmx4_accel.cu) which owns the device
    // context; this portable entry always has a complete exact result to
    // return, so a missing/unqualified kernel degrades transparently, never
    // fails closed with no output.
    switch (orient) {
    case GroupedMxfp4Orientation::Left:
        return GroupedMxfp4ProjectLeft(proj, mantissa, scale, n, m, out, shape, error);
    case GroupedMxfp4Orientation::Right:
        return GroupedMxfp4ProjectRight(mantissa, scale, proj, n, m, out, shape, error);
    }
    error = "LaunchGroupedMxfp4Projection: unknown orientation";
    return false;
}

} // namespace matmul_v4::cuda::cutlass_mxfp4

#endif // BITCOIN_CUDA_MATMUL_V4_BMX4_CUTLASS_MXFP4_H
