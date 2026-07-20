// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_LT_MX_NATIVE_H
#define BITCOIN_CUDA_MATMUL_V4_LT_MX_NATIVE_H

#include <matmul/matmul_v4_lt_mx_exact.h>

#include <cstdint>
#include <vector>

// NVIDIA CUDA native MXFP4 / block-scaled FP8 attempt surface for ENC-DR-LT B̂·V.
//
// Breakthrough thesis (Lever-B projection): Q = (μ · 2^e) · V with |μ| ≤ 6 (M11),
// |V| ≤ 6, e ∈ {0..3}, n ≤ 4096 ⇒ |Q| ≤ 288·n = 1,179,648 ≪ 2^24. FP32 accumulate
// can therefore be bit-exact for these integers; admit only after FP32→int32
// exactness + CPU oracle (see LtMxProjectionFitsFloat32ExactInteger).
//
// Preferred path — MXFP8 / block-32 UE8M0 (matches BTX block-32 E8M0):
//   pack μ as FP8 E4M3 integer mantissas; scales as UE8M0 with biased code 127+e;
//   pack V as FP8 with unit scales; cuBLASLt CUBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0,
//   CUBLAS_COMPUTE_32F, D as FP32; nearbyint / exact-integer gate; oracle match.
//
// Secondary — MXFP4 / E2M1:
//   Prefer OCP-style block-32 UE8M0 (same scale mode as MXFP8). Stock NVFP4 is often
//   VEC16_UE4M3 (NOT BTX block-32); that packing is tried only as a documented
//   duplicate-scale fallback and still requires oracle identity.
//
// Exactness gate (mandatory):
//   Compare every admitted output to ComputeProjectedRightMxBlockScaleLT.
//   Set native_*_qualified ONLY on full byte match across the self-qual suite.
//   Float accumulate is never labeled ExactGemm without oracle match.
//
// Dispatch order for MXFP4: cuBLASLt attempt, then CUTLASS SM120 OCP MXFP4
// (matmul_v4_lt_cutlass_mxfp4.*) when headers/arch allow; else fail closed.
// This header never raises activation heights and never claims C-15 closed.

namespace matmul_v4::cuda {

/** CUDA runtime-header version used to compile the native-MX translation unit
 *  (for example 13020 for CUDA 13.2), or zero in a non-CUDA build. */
[[nodiscard]] uint32_t LtCudaCompiledRuntimeVersion();

/** True only when the CUDA 12.8+ cuBLASLt block-scale API surface was compiled
 *  into this binary. This is compile evidence, not a silicon qualification. */
[[nodiscard]] bool IsLtCudaCublasLtBlockScaleApiCompiled();

/** Process-local native-lane snapshot (defaults fail-closed). */
[[nodiscard]] matmul::v4::lt::MxLaneProvenance ProbeLtCudaMxNativeProvenance();

/** True only after a real cuBLASLt/CUTLASS MXFP4 path self-qualified
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

/** Run the process-local one-time native self-qual. Calls are idempotent; true
 *  means at least one native MX lane qualified against the CPU oracle. */
[[nodiscard]] bool SelfQualifyLtNativeMxLanesOnce();

/** True on Blackwell-class GPUs (sm_10x / sm_12x) where peak MXFP4/FP8 is expected. */
[[nodiscard]] bool IsLtPeakMxCapableDevice();

/** Peak-path status after native self-qual (see matmul::v4::lt::LtPeakMxPathStatus). */
[[nodiscard]] matmul::v4::lt::LtPeakMxPathStatus ProbeLtPeakMxPathStatus();

/** One-shot diagnostics: resident-native ready vs deficit / how to fix. */
void DiagnoseLtPeakMxPathOnce();

/** True only when explicit native-only mode was requested but the end-to-end
 *  resident native path is not wired and oracle-qualified. */
[[nodiscard]] bool LtPeakMxBlocksDeviceResident();

} // namespace matmul_v4::cuda

#endif // BITCOIN_CUDA_MATMUL_V4_LT_MX_NATIVE_H
