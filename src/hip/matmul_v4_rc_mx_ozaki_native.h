// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_HIP_MATMUL_V4_RC_MX_OZAKI_NATIVE_H
#define BTX_HIP_MATMUL_V4_RC_MX_OZAKI_NATIVE_H

#include <cstdint>
#include <string>
#include <vector>

// ENC_RC Amendment 1.B — HIP/ROCm Ozaki native MXFP4 attempt (CDNA4 gfx950).
//
// hipBLASLt block-scaled path: HIP_R_4F_E2M1 +
// HIPBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0 with layout opA=T, opB=N (VEC32).
//
// Capability gate: configure-time BTX_HIP_MXFP4_TYPES (CMake
// check_cxx_source_compiles). NEVER use #if defined(HIP_R_4F_E2M1) — enums are
// not macros (same class of bug as defined(CUDA_R_*)).
//
// Native latch stays false without gfx950 silicon (or gfx942 FP8 after a
// separate arch-key self-qual). ExactGemm INT8 panels ≠ native MX float.
//
// Qualifying device test: rc_hip_ozaki_mxfp4_device_qualify
// Host pack unit-exact test: rc_hip_ozaki_mxfp4_pack_unit_exact
// HARD BLOCKER deficit: "requires gfx950 silicon" (MXFP4) /
//                       "requires gfx942 silicon" (FP8 lane)

namespace matmul_v4::hip {

inline constexpr uint32_t kRcOzakiHipMxBlk = 32;

[[nodiscard]] bool IsRcOzakiHipCompiled();

/** HARD BLOCKER token when device cannot qualify. */
[[nodiscard]] std::string RcOzakiHipDeficit();

// --- Host pack (unit-byte-exact; no device required) ---
// Pack int8 MX-factorable panels into E2M1 nibbles + UE8M0 scales for
// hipBLASLt opA=T opB=N VEC32 layout.
struct RcOzakiHipMxPack {
    std::vector<uint8_t> a_e2m1;   // opA=T: K×M packed
    std::vector<uint8_t> b_e2m1;   // opB=N: K×N packed
    std::vector<uint8_t> sfa_ue8m0; // M × kblocks
    std::vector<uint8_t> sfb_ue8m0; // N × kblocks
    uint32_t kblocks{0};
};

[[nodiscard]] bool PackRcOzakiHipMxfp4OpATOpBN(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, RcOzakiHipMxPack& out, std::string* error = nullptr);

/** Decode one E2M1 nibble → M11 mantissa (host oracle). */
[[nodiscard]] int8_t DecodeRcOzakiHipE2M1Nibble(uint8_t nib);

/** Host reference GEMM from packed MX panels (scalar dequant) → int64.
 *  Exact vs dense int8 product when panels are MX-factorable. Never sets
 *  native_* qualified. */
[[nodiscard]] bool HostReferenceRcOzakiHipMxfp4GemmFromPack(
    const RcOzakiHipMxPack& pack, uint32_t rows, uint32_t inner, uint32_t cols,
    std::vector<int64_t>& out, std::string* error = nullptr);

// --- ExactGemm panels (MFMA INT8 when HIP ON; not native MX) ---
[[nodiscard]] bool IsRcOzakiHipExactPanelsQualified();
[[nodiscard]] bool SelfQualifyRcOzakiHipExactPanelsOnce();
[[nodiscard]] bool TryLaunchRcOzakiHipExactPanelsGemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out, std::string* error = nullptr);

// --- Native block-scaled MXFP4 (gfx950 only after oracle self-qual) ---
[[nodiscard]] bool IsRcOzakiHipMxfp4Qualified();
[[nodiscard]] std::string RcOzakiHipMxfp4ArchKey();
[[nodiscard]] std::string RcOzakiHipMxfp4Backend();
[[nodiscard]] std::string RcOzakiHipMxfp4Deficit();
[[nodiscard]] bool SelfQualifyRcOzakiHipMxfp4Once();
[[nodiscard]] bool TryLaunchRcOzakiHipMxfp4GemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out, std::string* error = nullptr);

void ResetRcOzakiHipQualForTest();

} // namespace matmul_v4::hip

#endif // BTX_HIP_MATMUL_V4_RC_MX_OZAKI_NATIVE_H
