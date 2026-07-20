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

// ENC_RC Amendment 1.B — Ozaki / limb-split native MXFP4 scaffold.
// Plan: doc/btx-matmul-v4.5-rc-native-fp4-ozaki-plan-2026-07-20.md
//
// LT native MXFP4 (bounds <2^24) does NOT admit RC Phase-1 Z=S·V (~2^30.76)
// or wgrad (>2^24). Until an Ozaki device path qualifies vs the int64 oracle
// at consensus dims, every TryRcOzakiMxfp4* entry is fail-closed and
// IsRcOzakiMxfp4Qualified() / ProbeRCSelfQual native_mxfp4 stay false.

namespace matmul::v4::rc {

/** Max K-chunk for a single ExactGemm / future FP4 sub-GEMM under 2304·K < 2^24.
 *  Matches kRCWgradExactChunk; Ozaki panels must not exceed this without a
 *  separate bound proof. */
inline constexpr uint32_t kRCOzakiExactChunk = kRCWgradExactChunk;

struct RCOzakiMxfp4Status {
    bool attempted{false};
    bool qualified{false}; // always false until device Ozaki quals vs int64
    std::string deficit_reason{"ozaki_mxfp4_not_wired"};
};

/** Process-wide latch: native MXFP4 Ozaki path admitted for RC. Always false
 *  in this scaffold; never inherit LT native_mxfp4_qualified. */
[[nodiscard]] bool IsRcOzakiMxfp4Qualified();

[[nodiscard]] RCOzakiMxfp4Status ProbeRcOzakiMxfp4Status();

/**
 * Device / vendor MXFP4 Ozaki GEMM → int64 (rows×cols).
 * Always fail-closed in this scaffold (clears out, returns false).
 * Future: limb / panel FP4 sub-GEMMs with exact integer recombine matching
 * ExactGemmS32S8ViaRadix256-style reconstruction.
 */
[[nodiscard]] bool TryRcOzakiMxfp4GemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out);

/**
 * CPU reference Ozaki limb/panel split: ExactGemmS8S8 panels with
 * K_chunk ≤ kRCOzakiExactChunk, accumulate into int64.
 * Byte-identical to a dense int64 GEMM when |L|,|R| ≤ 48 (RC M11·2^e bound
 * proxy used in tests). Does NOT set IsRcOzakiMxfp4Qualified / native_*.
 */
[[nodiscard]] bool RcOzakiCpuLimbSplitGemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out,
    const matmul::v4::lt::ExactGemmBackend& gemm = {});

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_MX_OZAKI_H
