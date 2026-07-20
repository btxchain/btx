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
//   2) Native block-scaled MXFP4 Ozaki — only after a real MXFP4 device kernel
//      matches the int64 oracle (no hidden LaunchGemmS8S8 / CPU fallback in the
//      native claim). SM120 and SM100 qualify on separate arch_key latches.
//
// Never copy LT native_mxfp4_qualified. Never raise nMatMulRCHeight.

namespace matmul::v4::rc {

inline constexpr uint32_t kRCOzakiExactChunk = kRCWgradExactChunk;

struct RCOzakiMxfp4Status {
    bool attempted{false};
    bool qualified{false}; // native MXFP4 only
    bool exact_panels_qualified{false};
    /** "mxfp4_blockscaled_device" | "mxfp4_cutlass_sm120" | "mxfp4_cutlass_sm100" | "" */
    std::string backend;
    std::string arch_key; // e.g. sm_120 / sm_100
    std::string deficit_reason;
};

[[nodiscard]] bool IsRcOzakiExactPanelsQualified();
[[nodiscard]] bool IsRcOzakiMxfp4Qualified();

[[nodiscard]] RCOzakiMxfp4Status ProbeRcOzakiMxfp4Status();

[[nodiscard]] bool SelfQualifyRcOzakiExactPanelsOnce();
[[nodiscard]] bool SelfQualifyRcOzakiMxfp4Once();

/**
 * Native MXFP4 Ozaki → int64. Succeeds only when IsRcOzakiMxfp4Qualified()
 * (real block-scaled MXFP4 device path; no INT8 ExactGemm inside this entry).
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

void ResetRcOzakiQualForTest();

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_MX_OZAKI_H
