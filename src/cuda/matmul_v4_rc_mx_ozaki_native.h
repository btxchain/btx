// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_CUDA_MATMUL_V4_RC_MX_OZAKI_NATIVE_H
#define BTX_CUDA_MATMUL_V4_RC_MX_OZAKI_NATIVE_H

#include <cstdint>
#include <string>
#include <vector>

// ENC_RC Ozaki device backends (Amendment 1.B).
// ExactGemm panels ≠ native MXFP4. Native path must not call LaunchGemmS8S8.
//
// Selected backend honesty (PR #89 Workstream B / Agent C dispatch):
//   Unqualified | SM120_MMA | SM100_CUBLASLT
// A backend latches ONLY after THAT same backend passes the COMPLETE suite.
// Never combine partial MMA evidence with cuBLASLt and mislabel as MMA/cutlass.
// Never report dense INT8 / scalar-decode as native MXFP4.
//
// SM120_MMA / native MXFP4 may be advertised ONLY if ALL of:
//   1) Compatible SM120 device present
//   2) RcOzakiMxfp4Sm120aKernelLinked() == true (dedicated sm_120a object linked;
//      plain -arch=sm_120 fatbins without that object stay fail-closed)
//   3) Self-qualification success (complete suite for THAT backend)
//   4) Exact CPU differential (suite vs int64 oracle) pass
//   5) Existing project SASS/instruction quals if any (rack Workstream G)
// Any miss → SelectedBackend=Unqualified, qualified=false, deficit token below.
//
// Deficit tokens (primary; detail may follow after ':'):
//   not_linked | unsupported_arch | selfqual_failed | device_unavailable |
//   scalar-decode_exact_but_not_native_tensor | …
//
// Block-scaled mxf8f6f4 PTX is compiled IN only under
// __CUDA_ARCH_SPECIFIC__==1200 (feature-qualified sm_120a), not plain sm_120.
// BTX_LT_CUTLASS_MXFP4 remains fail-closed scaffolding — not a consumer
// SM120 native admission path; do not mislabel it as SM120_MMA.
//
// SASS expectation for rack Workstream G (sm_120a, CUDA 13.2):
//   After SM120_MMA qualifies, capture SASS and confirm QMMA.SF E2M1
//   (mma.sync kind::mxf8f6f4.block_scale … e2m1.e2m1 … ue8m0) appears in the
//   rc_ozaki_mxfp4_mma_gemm kernel. Suggested:
//     cuobjdump -sass <libbtx_matmul_backend.so> | rg -n 'QMMA|mma\.|E2M1|mxf8f6f4'
//     ncu --devices 0 --set full ./src/test/test_btx -t rc_ozaki_mxfp4_native_gate
// SM100/B200 is a separate latch (SM100_CUBLASLT); never infer from SM120.

namespace matmul_v4::cuda {

/** Honest selected native MXFP4 backend after full-suite self-qual. */
enum class RcOzakiMxfp4SelectedBackend : uint8_t {
    Unqualified = 0,
    SM120_MMA = 1,       // hand QMMA.SF m16n8k32 e2m1 block_scale (not CUTLASS)
    SM100_CUBLASLT = 2,  // cuBLASLt CUDA_R_4F_E2M1 + VEC32_UE8M0 on sm_100
};

/**
 * Link-time capability: true only when the sm_120a marker TU
 * (matmul_v4_rc_mx_ozaki_native_sm120a.cu) is linked via
 * BTX_CUDA_SM120_MXFP4_NATIVE. Weak stub returns false when that TU is absent
 * (plain sm_120 / no-CUDA builds). Self-qual must consult this before
 * advertising SM120_MMA.
 */
[[nodiscard]] bool RcOzakiMxfp4Sm120aKernelLinked();

[[nodiscard]] bool IsRcOzakiCudaCompiled();

// --- ExactGemm IMMA panels (not native MXFP4) ---
[[nodiscard]] bool IsRcOzakiCudaExactPanelsQualified();
[[nodiscard]] bool SelfQualifyRcOzakiCudaExactPanelsOnce();
[[nodiscard]] bool TryLaunchRcOzakiExactPanelsGemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out, std::string* error = nullptr);

// --- Block-scaled MXFP4 ---
// Scalar-decode E2M1+FP32 may probe exactness (backend contains "scalar-decode")
// but must NEVER flip IsRcOzakiCudaMxfp4Qualified / SelectedBackend.
[[nodiscard]] bool IsRcOzakiCudaMxfp4Qualified();
[[nodiscard]] RcOzakiMxfp4SelectedBackend RcOzakiCudaMxfp4SelectedBackend();
[[nodiscard]] std::string RcOzakiCudaMxfp4ArchKey();
/** "Unqualified" | "SM120_MMA" | "SM100_CUBLASLT" |
 *  "mxfp4_blockscaled_device_scalar-decode" (exactness only; native false). */
[[nodiscard]] std::string RcOzakiCudaMxfp4Backend();
/** Machine-readable deficit; empty when SelectedBackend is SM120_MMA/SM100_CUBLASLT. */
[[nodiscard]] std::string RcOzakiCudaMxfp4Deficit();
/** Native QMMA/cuBLASLt panel launches (excludes scalar-tail K%32 remainder). */
[[nodiscard]] uint64_t RcOzakiCudaMxfp4NativeTensorLaunchCount();
/** Scalar-decode tail launches (K remainder); never counts as MMA evidence. */
[[nodiscard]] uint64_t RcOzakiCudaMxfp4ScalarTailLaunchCount();
[[nodiscard]] bool SelfQualifyRcOzakiCudaMxfp4Once();

/**
 * Succeeds only when SelectedBackend is SM120_MMA or SM100_CUBLASLT.
 * Dispatches ONLY that backend — no silent fallback to the other or to
 * scalar-decode / dense INT8.
 */
[[nodiscard]] bool TryLaunchRcOzakiMxfp4GemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out, std::string* error = nullptr);

/**
 * Device-pointer entry for resident solvers (Workstream C).
 * d_left: rows×inner int8 row-major; d_right: inner×cols int8 row-major;
 * d_out: rows×cols int64. `cuda_stream` is cudaStream_t (void* keeps header
 * CUDA-free). Uses reusable process arenas; does not cudaDeviceSynchronize —
 * caller owns stream ordering. Fail-closed unless SelectedBackend is set and
 * THAT backend serves the launch.
 */
[[nodiscard]] bool TryLaunchRcOzakiMxfp4GemmS8S8Int64Device(
    const int8_t* d_left, const int8_t* d_right, int64_t* d_out, uint32_t rows,
    uint32_t inner, uint32_t cols, void* cuda_stream, std::string* error = nullptr);

/** Grow-only scratch ensure for external resident pools (optional pre-warm). */
[[nodiscard]] bool EnsureRcOzakiMxfp4DeviceArena(size_t a_bytes, size_t b_bytes, size_t sfa_bytes,
                                                 size_t sfb_bytes, size_t d_elems,
                                                 size_t workspace_bytes = 0);

void ResetRcOzakiCudaQualForTest();

} // namespace matmul_v4::cuda

#endif // BTX_CUDA_MATMUL_V4_RC_MX_OZAKI_NATIVE_H
