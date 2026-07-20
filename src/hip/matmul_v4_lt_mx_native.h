// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HIP_MATMUL_V4_LT_MX_NATIVE_H
#define BITCOIN_HIP_MATMUL_V4_LT_MX_NATIVE_H

#include <matmul/matmul_v4_lt_mx_exact.h>

#include <cstdint>
#include <vector>

// AMD HIP/ROCm native MXFP4 / FP8 attempt surface for ENC-DR-LT B̂·V.
//
// CDNA4 (gfx950) hipBLASLt documents OCP MXFP4/MXFP8 with
// HIPBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0,
// HIPBLASLT_MATMUL_MATRIX_SCALE_BLK32_UE8M0_32_8_EXT (pre-swizzled), and
// HIP_R_4F_E2M1 / HIP_R_8F_E4M3 + HIP_R_8F_UE8M0. MFMA scale forms
// (V_MFMA_SCALE_F32_*_F8F6F4) are the silicon substrate. Miner-local only.
//
// Implementation: hip/matmul_v4_lt_mx_native.hip (HIP on) or
// hip/matmul_v4_lt_accel_stub.cpp (HIP off).
//
// Exactness gate (mandatory):
//   Compare every admitted output to ComputeProjectedRightMxBlockScaleLT.
//   Set native_*_qualified ONLY on full byte match across self-qual shapes.
//   Otherwise remain fail-closed and use exact INT8 scale-partitioned MFMA.
//
// This header never raises activation heights and never claims C-15 closed.

namespace matmul_v4::hip {

/** Process-local native-lane snapshot (defaults fail-closed). */
[[nodiscard]] matmul::v4::lt::MxLaneProvenance ProbeLtHipMxNativeProvenance();

/** True only after a real hipBLASLt/rocBLAS MXFP4 path self-qualified
 *  bit-identical to the CPU MX oracle. Never true from arch name alone. */
[[nodiscard]] bool IsLtNativeMxfp4Qualified();

/** True only after a real block-scaled FP8 path self-qualified likewise. */
[[nodiscard]] bool IsLtNativeFp8Qualified();

/** Attempt native MXFP4 block-scaled B̂·V. On success `out` is byte-identical
 *  to ComputeProjectedRightMxBlockScaleLT and provenance.native_mxfp4_qualified
 *  is set. Otherwise returns false without writing a digest-capable result. */
[[nodiscard]] bool TryLaunchNativeMxfp4ProjectedRight(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m, std::vector<int32_t>& out,
    matmul::v4::lt::MxLaneProvenance* provenance = nullptr);

/** Attempt native/block-scaled FP8 B̂·V under the same exactness gate. */
[[nodiscard]] bool TryLaunchNativeFp8ProjectedRight(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m, std::vector<int32_t>& out,
    matmul::v4::lt::MxLaneProvenance* provenance = nullptr);

/** True on CDNA4 gfx950 where peak MXFP4/FP8 is expected. */
[[nodiscard]] bool IsLtPeakMxCapableDevice();

/** Peak-path status after native self-qual (see matmul::v4::lt::LtPeakMxPathStatus). */
[[nodiscard]] matmul::v4::lt::LtPeakMxPathStatus ProbeLtPeakMxPathStatus();

/** One-shot LogPrintf diagnostics: peak ready vs deficit / how to fix. */
void DiagnoseLtPeakMxPathOnce();

/** True when peak silicon requires native and it is not qualified (blocks resident). */
[[nodiscard]] bool LtPeakMxBlocksDeviceResident();

} // namespace matmul_v4::hip

#endif // BITCOIN_HIP_MATMUL_V4_LT_MX_NATIVE_H
