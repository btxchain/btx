// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_METAL_MATMUL_V4_RC_OZAKI_ACCEL_H
#define BTX_METAL_MATMUL_V4_RC_OZAKI_ACCEL_H

#include <cstdint>
#include <string>
#include <vector>

// ENC_RC Ozaki / coupled ExactGemm panels on Apple Metal.
//
// Two admissions (do not conflate):
//   1) ExactGemm K-panel Ozaki → int64 via Metal TensorOps / simdgroup_matrix
//      (or MSL ALU) when Apple silicon + Metal self-qual passes.
//   2) Native OCP MXFP4 — NOT admitted on Metal (Apple MX·E8M0 / FP8 dequant
//      is not proven bit-identical to RC int64 Ozaki). Never label INT8 as
//      native MX float.
//
// Linux / non-Darwin: host .cpp provides unit-byte-exact reference paths;
// device latches stay false with HARD BLOCKER
//   "requires Apple silicon + Metal"
// Qualifying device test (Darwin + Metal ON):
//   rc_metal_ozaki_exact_panels_device_qualify
// Host unit-exact test (all platforms):
//   rc_metal_ozaki_exact_panels_host_byte_exact
//
// Heights stay INT32_MAX. GKR arbiter stays OFF.

namespace matmul_v4::metal {

/** True when this binary compiled the Metal RC Ozaki .mm TU (not the host .cpp). */
[[nodiscard]] bool IsRcOzakiMetalCompiled();

/** HARD BLOCKER token when device cannot qualify on this host. */
[[nodiscard]] std::string RcOzakiMetalDeficit();

// --- Host reference (always unit-byte-exact vs int64 oracle) ---
[[nodiscard]] bool HostReferenceRcOzakiExactPanelsGemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out, std::string* error = nullptr);

// --- ExactGemm panels (Metal TensorOps / ALU when available) ---
/** True after SelfQualify attempted a Metal ExactGemm surface. */
[[nodiscard]] bool IsRcOzakiMetalExactPanelsAttempted();
[[nodiscard]] bool IsRcOzakiMetalExactPanelsQualified();
/** Honest execution label: "metal_int8_mpp_tensorops" | "metal_int8_msl_alu" | "".
 *  Never "OCP MXFP4". */
[[nodiscard]] std::string RcOzakiMetalExactPanelsBackend();
[[nodiscard]] bool SelfQualifyRcOzakiMetalExactPanelsOnce();
[[nodiscard]] bool TryLaunchRcOzakiMetalExactPanelsGemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out, std::string* error = nullptr);

// --- Native MXFP4 (always fail-closed on Metal — not an INT8 masquerade) ---
[[nodiscard]] bool IsRcOzakiMetalMxfp4Qualified();
[[nodiscard]] std::string RcOzakiMetalMxfp4Backend();
[[nodiscard]] std::string RcOzakiMetalMxfp4ArchKey();
[[nodiscard]] bool SelfQualifyRcOzakiMetalMxfp4Once();
[[nodiscard]] bool TryLaunchRcOzakiMetalMxfp4GemmS8S8Int64(
    const std::vector<int8_t>& left, const std::vector<int8_t>& right, uint32_t rows,
    uint32_t inner, uint32_t cols, std::vector<int64_t>& out, std::string* error = nullptr);

void ResetRcOzakiMetalQualForTest();

} // namespace matmul_v4::metal

#endif // BTX_METAL_MATMUL_V4_RC_OZAKI_ACCEL_H
