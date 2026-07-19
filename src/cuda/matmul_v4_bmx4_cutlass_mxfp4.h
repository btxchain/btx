// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_BMX4_CUTLASS_MXFP4_H
#define BITCOIN_CUDA_MATMUL_V4_BMX4_CUTLASS_MXFP4_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Scale-partitioned grouped MXFP4 projection lane (B200 / Blackwell).
//
// Design: doc/btx-matmul-v4.4-exact-accel-lanes.md §2.
// CPU reference: matmul::v4::bmx4::ComputeProjected{Left,Right}ScalePartitionedBMX4C.
//
// TWO datapaths, ONE exact result (the committed OCP-MX E2M1/E8M0 object is
// vendor-neutral: every path below produces byte-identical int32 output):
//
//   (1) PORTABLE EXACT (this header, ALWAYS compiled/available): a complete
//       integer scale-partitioned grouped projection. For each OCP block along
//       the committed-scale axis it partitions the contraction index into the
//       four E8M0 exponent buckets J_e, evaluates the four reduced-K products
//       (total K = n, NOT 4n), and folds each with the exact power-of-two
//       shift 2^e. Pure integer arithmetic, no rounding, no float. This is the
//       "used when CUTLASS is unavailable" path required by the exact-lane
//       contract, and it is what the CPU/device-ALU tiers run today.
//
//   (2) CUTLASS TENSOR KERNEL (hardware-gated, BTX_BMX4C_CUTLASS_MXFP4): a real
//       persistent grouped GEMM on qualified Blackwell (tcgen05 mxf4). It
//       replaces path (1) ONLY after the toolkit + silicon are present AND the
//       device passes M-t24 + scale-partitioned qualification. cuBLAS 13.x
//       serves NVFP4 (UE4M3/16) but not OCP MXFP4 (E2M1 + E8M0/32), so CUTLASS
//       is the only vendor route for the committed alphabet; until it is linked
//       and qualified, IsGroupedMxfp4TensorKernelLinked() is false and callers
//       transparently use path (1).
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
//   * Every mantissa product <= 36; every bucket accumulation <= 36n < 2^21,
//     so a proven 24-bit FP32 accumulator is exact (path (2)); path (1)
//     accumulates in int32, exact for the full committed magnitude window.
//   * Apply 2^e in the exact integer epilogue; do not reorient committed scales.
//
// Grouped problem shape for one 32-element committed-scale block:
//   for e in {0,1,2,3}:
//     K_e = |{ j : committed_scale(block, j) = e }|
//     partial_e = Left_block * Right_bucket_e   (K = K_e)
//   Out_block += sum_e (partial_e << e)
// Total K across the four buckets equals n, not 4n.

namespace matmul_v4::cuda::cutlass_mxfp4 {

// OCP-MX committed-scale constants (mirror matmul::v4::bmx4::kBlockLen /
// kNumScaleCodes; duplicated here so this header stays dependency-light and
// usable from any translation unit, CUDA or portable C++).
inline constexpr uint32_t kBlockLen = 32;      // OCP block length L
inline constexpr uint32_t kNumScaleCodes = 4;  // committed E8M0 codes e in {0..3}

// Which committed operand a projection contracts. Left = P = U * Ahat (scale is
// constant on 32-column blocks of Ahat's OTHER axis); Right = Q = Bhat * V.
enum class GroupedMxfp4Orientation : uint8_t {
    Left = 0,   // P[a][k] = sum_i U[a][i] * mu_a[i][k] * 2^{e_a(i, k/32)}
    Right = 1,  // Q[k][c] = sum_j mu_b[k][j] * 2^{e_b(k/32, j)} * V[j][c]
};

// Per-call telemetry describing the grouped partition that was executed. The
// K_e counts are summed over every committed block; K_total is their sum and
// equals n * (n / kBlockLen) (one full contraction axis per block).
struct GroupedMxfp4Problem {
    uint32_t M{0};
    uint32_t N{0};
    uint64_t K_e[kNumScaleCodes]{0, 0, 0, 0}; // partition of K, summed over blocks
    uint64_t K_total{0};                       // sum == n * (n / kBlockLen)
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
// Portable exact grouped-MXFP4 LEFT projection.
//   P[a][k] = sum_i U[a][i] * mu_a[i][k] * 2^{e_a(i, k/32)}   (m x n row-major)
// For each 32-column block kb, rows i are partitioned by their committed scale
// e_a(i, kb) into buckets; each bucket contributes an exact reduced-K product
// U[:, J_e] * A_e[J_e, block] that is folded with the power-of-two shift 2^e.
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

    std::vector<uint32_t> bucket[kNumScaleCodes];
    std::vector<int8_t> U_e;
    std::vector<int8_t> A_e;

    for (uint32_t kb = 0; kb < nblk; ++kb) {
        for (auto& b : bucket) b.clear();
        for (uint32_t i = 0; i < n; ++i) {
            const uint8_t e = scale_a[static_cast<size_t>(i) * nblk + kb];
            if (e >= kNumScaleCodes) {
                error = "GroupedMxfp4ProjectLeft: scale code out of range";
                return false;
            }
            bucket[e].push_back(i);
        }
        for (uint32_t e = 0; e < kNumScaleCodes; ++e) {
            const uint32_t Ke = static_cast<uint32_t>(bucket[e].size());
            if (shape != nullptr) {
                shape->K_e[e] += Ke;
                shape->K_total += Ke;
            }
            if (Ke == 0) continue;
            U_e.resize(static_cast<size_t>(m) * Ke);
            A_e.resize(static_cast<size_t>(Ke) * kBlockLen);
            for (uint32_t t = 0; t < Ke; ++t) {
                const uint32_t i = bucket[e][t];
                for (uint32_t a = 0; a < m; ++a) {
                    U_e[static_cast<size_t>(a) * Ke + t] = U[static_cast<size_t>(a) * n + i];
                }
                for (uint32_t c = 0; c < kBlockLen; ++c) {
                    A_e[static_cast<size_t>(t) * kBlockLen + c] =
                        mu_a[static_cast<size_t>(i) * n + kb * kBlockLen + c];
                }
            }
            // partial = U_e[m x Ke] * A_e[Ke x 32], then P += partial << e.
            for (uint32_t a = 0; a < m; ++a) {
                for (uint32_t c = 0; c < kBlockLen; ++c) {
                    int32_t acc = 0;
                    for (uint32_t t = 0; t < Ke; ++t) {
                        acc += static_cast<int32_t>(U_e[static_cast<size_t>(a) * Ke + t]) *
                               static_cast<int32_t>(A_e[static_cast<size_t>(t) * kBlockLen + c]);
                    }
                    // 2^e via multiplication (not a signed shift: acc may be
                    // negative; e in {0..3}, so 1<<e is exact). Matches the CPU
                    // reference / Bmx4PromoteShiftedKernel discipline.
                    P_out[static_cast<size_t>(a) * n + kb * kBlockLen + c] += acc * (1 << e);
                }
            }
        }
    }
    error.clear();
    return true;
}

// ---------------------------------------------------------------------------
// Portable exact grouped-MXFP4 RIGHT projection.
//   Q[k][c] = sum_j mu_b[k][j] * 2^{e_b(k/32, j)} * V[j][c]   (n x m row-major)
// For each 32-row block rb, columns j are partitioned by committed scale
// e_b(rb, j); each bucket contributes B_e[block x J_e] * V[J_e, :] folded with
// 2^e. Byte-identical to ComputeProjectedRightScalePartitionedBMX4C.
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

    std::vector<uint32_t> bucket[kNumScaleCodes];
    std::vector<int8_t> B_e;
    std::vector<int8_t> V_e;

    for (uint32_t rb = 0; rb < nblk; ++rb) {
        for (auto& b : bucket) b.clear();
        const size_t srow = static_cast<size_t>(rb) * n;
        for (uint32_t j = 0; j < n; ++j) {
            const uint8_t e = scale_b[srow + j];
            if (e >= kNumScaleCodes) {
                error = "GroupedMxfp4ProjectRight: scale code out of range";
                return false;
            }
            bucket[e].push_back(j);
        }
        for (uint32_t e = 0; e < kNumScaleCodes; ++e) {
            const uint32_t Ke = static_cast<uint32_t>(bucket[e].size());
            if (shape != nullptr) {
                shape->K_e[e] += Ke;
                shape->K_total += Ke;
            }
            if (Ke == 0) continue;
            B_e.resize(static_cast<size_t>(kBlockLen) * Ke);
            V_e.resize(static_cast<size_t>(Ke) * m);
            for (uint32_t t = 0; t < Ke; ++t) {
                const uint32_t j = bucket[e][t];
                for (uint32_t r = 0; r < kBlockLen; ++r) {
                    B_e[static_cast<size_t>(r) * Ke + t] =
                        mu_b[static_cast<size_t>(rb * kBlockLen + r) * n + j];
                }
                for (uint32_t c = 0; c < m; ++c) {
                    V_e[static_cast<size_t>(t) * m + c] = V[static_cast<size_t>(j) * m + c];
                }
            }
            for (uint32_t r = 0; r < kBlockLen; ++r) {
                for (uint32_t c = 0; c < m; ++c) {
                    int32_t acc = 0;
                    for (uint32_t t = 0; t < Ke; ++t) {
                        acc += static_cast<int32_t>(B_e[static_cast<size_t>(r) * Ke + t]) *
                               static_cast<int32_t>(V_e[static_cast<size_t>(t) * m + c]);
                    }
                    Q_out[static_cast<size_t>(rb * kBlockLen + r) * m + c] += acc * (1 << e);
                }
            }
        }
    }
    error.clear();
    return true;
}

/** Launch the scale-partitioned grouped MXFP4 projection for one operand.
 *  Dispatches to the CUTLASS tensor kernel when it is linked AND qualified
 *  (path (2)); otherwise runs the complete portable exact integer path (1).
 *  Fills `shape` telemetry (bucket partition) when non-null. Returns false and
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
