// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_MX_OZAKI_H
#define BTX_MATMUL_MATMUL_V4_RC_MX_OZAKI_H

#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc.h>

#include <cstdint>
#include <string>
#include <vector>

// ENC_RC Amendment 1.B — Ozaki / limb-split paths.
// Plan: doc/btx-matmul-v4.5-rc-native-fp4-ozaki-plan-2026-07-20.md
//
// Two distinct admissions (do not conflate):
//   1) ExactGemm K-panel Ozaki (IMMA/CPU) — mining accelerator; NEVER sets
//      ProbeRCSelfQual.native_mxfp4_qualified.
//   2) Native block-scaled MXFP4 Ozaki — only after a real tensor backend
//      (SM120_MMA or SM100_CUBLASLT) matches the int64 oracle on a COMPLETE
//      suite for THAT backend alone. Scalar E2M1+FP32 decode and dense INT8
//      / LaunchGemmS8S8 never set the native latch. SM120 and SM100 qualify
//      on separate arch_key latches — never infer one from the other.
//
// SM120_MMA additionally requires matmul_v4::cuda::RcOzakiMxfp4Sm120aKernelLinked()
// (dedicated sm_120a object). Plain sm_120 builds without that object report
// Unqualified + deficit "not_linked" and native_mxfp4_qualified=false.
// BTX_LT_CUTLASS_MXFP4 is NOT a consumer native admission path (fail-closed).
//
// Never copy LT native_mxfp4_qualified. Never raise nMatMulRCHeight.

namespace matmul::v4::rc {

inline constexpr uint32_t kRCOzakiExactChunk = kRCWgradExactChunk;

/** Mirrors matmul_v4::cuda::RcOzakiMxfp4SelectedBackend for host probes. */
enum class RCOzakiMxfp4SelectedBackend : uint8_t {
    Unqualified = 0,
    SM120_MMA = 1,
    SM100_CUBLASLT = 2,
    SM100_MMA = 3, // hand tcgen05.mma.block_scale on sm_100a (B200)
};

struct RCOzakiMxfp4Status {
    bool attempted{false};
    bool qualified{false}; // native MXFP4 tensor only
    bool exact_panels_qualified{false};
    /** True when the dedicated sm_120a kernel object is linked (packaging). */
    bool sm120a_kernel_linked{false};
    RCOzakiMxfp4SelectedBackend selected{RCOzakiMxfp4SelectedBackend::Unqualified};
    /** "SM120_MMA" | "SM100_CUBLASLT" | "Unqualified" |
     *  "mxfp4_blockscaled_device_scalar-decode" | "" */
    std::string backend;
    std::string arch_key; // e.g. sm_120 / sm_100 — never cross-inferred
    /** Primary tokens: not_linked | unsupported_arch | selfqual_failed | … */
    std::string deficit_reason;
};

[[nodiscard]] bool IsRcOzakiExactPanelsQualified();
[[nodiscard]] bool IsRcOzakiMxfp4Qualified();
/** Packaging probe: wraps matmul_v4::cuda::RcOzakiMxfp4Sm120aKernelLinked(). */
[[nodiscard]] bool IsRcOzakiMxfp4Sm120aKernelLinked();

[[nodiscard]] RCOzakiMxfp4Status ProbeRcOzakiMxfp4Status();

[[nodiscard]] bool SelfQualifyRcOzakiExactPanelsOnce();
[[nodiscard]] bool SelfQualifyRcOzakiMxfp4Once();

/**
 * Native MXFP4 Ozaki → int64. Succeeds only when IsRcOzakiMxfp4Qualified()
 * and the selected backend serves the call (no silent backend switch).
 */
[[nodiscard]] bool TryRcOzakiMxfp4GemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out);

/**
 * ExactGemm K-panel Ozaki → int64 (CUDA IMMA when available, else CPU ExactGemm).
 * Does not set native_mxfp4_qualified.
 */
[[nodiscard]] bool TryRcOzakiExactPanelsGemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out,
    const matmul::v4::lt::ExactGemmBackend& gemm = {});

/** CPU reference panel split (tests / oracle). Does not flip any qual latch. */
[[nodiscard]] bool RcOzakiCpuLimbSplitGemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out,
    const matmul::v4::lt::ExactGemmBackend& gemm = {});

/**
 * Exact base-4 limb decomposition (F4 / WP-D):
 *   x = sign(x)·Σ_{j=0..3} digit_j · 2^(2j),  digit_j ∈ {0,1,2,3}.
 * Totality for every int8 including -128 without storing +128. Writes four
 * signed digit planes (values in {-3..3}) such that
 *   vals[i] == Σ_j planes[j][i] · 2^(2j).
 */
void DecomposeInt8Base4Planes(const int8_t* vals, size_t count, std::vector<int8_t> planes[4]);

[[nodiscard]] bool RcOzakiOperandsFitMxFastPathAbs(const std::vector<int8_t>& a,
                                                   const std::vector<int8_t>& b);

[[nodiscard]] bool RcOzakiBase4LimbGemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out,
    const matmul::v4::lt::ExactGemmBackend& gemm = {});

void FillHighScaleMixedPanels(std::vector<int8_t>& left, std::vector<int8_t>& right,
                              uint32_t rows, uint32_t inner, uint32_t cols);

void ResetRcOzakiQualForTest();

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_MX_OZAKI_H
