// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_METAL_MATMUL_V4_LT_ACCEL_H
#define BITCOIN_METAL_MATMUL_V4_LT_ACCEL_H

#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_lt_mx_exact.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

// ---------------------------------------------------------------------------
// Apple Metal backend for MatMul v4.4 ENC-DR-LT (MatExpand).
//
// Digests MUST be byte-identical to ComputeDigestBMX4CLT.
// MX B̂·V MUST be byte-identical to ComputeProjectedRightMxBlockScaleLT.
//
// ExactGemm:
//   s8×s8 → prefers MPP TensorOps after ExactGemmS8S8 self-qual; else MSL ALU.
//   s32×s8 → MSL ALU only (no dedicated TensorOps shape). Never label ALU as
//   TensorOps.
//
// Lever-B MX honesty (this backend):
//   * Extract (ExtractMatExpandMxTileMantissas / DeriveMatExpandMxScale) stays
//     on the HOST. A device-resident ChaCha+SHA MX Extract twin is not shipped
//     here — bit-identity to the CPU oracles is harder than the four-partition
//     projection GEMMs, and CUDA/HIP already own that residency shape.
//   * B̂·V uses exact INT8 scale partitions e∈{0..3}: host gather of μ_e (or
//     the shared ComputeProjectedRightMxScalePartitionedGemmLT lowering) plus
//     Metal ExactGemmS8S8 (TensorOps or ALU) and exact <<e accumulate. This is
//     an MX-layout INT8 twin, NOT native OCP-MXFP4.
//   * Apple Metal 4.1+ documents FP8 / MX·E8M0 block-scale planes for ML
//     dequant inside matmul2d. That path is floating / vendor-dequant and is
//     NOT proven bit-identical to BTX M11×2^{e} with e∈{0..3}. Native
//     MXFP4/FP8 entry points therefore FAIL CLOSED (attempted=false,
//     qualified=false) until an exact self-qual path exists.
//
// Fail-closed without Apple/Metal or on ExactGemm / MX self-qual mismatch.
// Public activation heights remain INT32_MAX. C-15 remains OPEN.
// ---------------------------------------------------------------------------

namespace matmul_v4::metal {

/** Metal MX projection provenance (extends shared MxLaneProvenance). */
struct LtMetalMxProvenance {
    matmul::v4::lt::MxLaneProvenance mx{};
    /** Always true today: Lever-B Extract runs on the host oracle. */
    bool host_mx_extract{true};
    /** True when this call used Metal ExactGemm for the e∈{0..3} partitions. */
    bool metal_exact_gemm_projection{false};
    /** True when at least one partition GEMM used MPP TensorOps (not ALU). */
    bool projection_used_tensor_ops{false};
};

[[nodiscard]] bool IsMatMulLTMetalAvailable();

/** True after process-local MX projection self-qual vs
 *  ComputeProjectedRightMxBlockScaleLT (Metal ExactGemm partitions). */
[[nodiscard]] bool IsMatMulLTMetalMxProjectionAvailable();

[[nodiscard]] bool LaunchGemmS8S8(const std::vector<int8_t>& left,
                                  const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t inner, uint32_t cols,
                                  std::vector<int32_t>& out);
[[nodiscard]] bool LaunchGemmS32S8(const std::vector<int32_t>& left,
                                   const std::vector<int8_t>& right,
                                   uint32_t rows, uint32_t inner, uint32_t cols,
                                   std::vector<int32_t>& out);

/** Exact MX scale-partitioned B̂·V on Metal ExactGemm (e∈{0..3}).
 *  On success `out` is byte-identical to ComputeProjectedRightMxBlockScaleLT.
 *  Sets provenance.exact_mx_scale_partitioned; never sets native_*_qualified.
 *  Returns false → caller MUST use the CPU oracle. */
[[nodiscard]] bool LaunchProjectedRightMxBlockScaleLT(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m, std::vector<int32_t>& out,
    LtMetalMxProvenance* provenance = nullptr);

/** ExactMxProjectionBackend::Fn adapter (shared dispatch hook). */
[[nodiscard]] bool TryLaunchLtMetalMxProjectRight(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m, std::vector<int32_t>& out,
    matmul::v4::lt::MxLaneProvenance* provenance);

/** Injectable ExactMxProjectionBackend pointing at TryLaunchLtMetalMxProjectRight
 *  when IsMatMulLTMetalMxProjectionAvailable(); else empty (CPU oracle). */
[[nodiscard]] matmul::v4::lt::ExactMxProjectionBackend MakeMetalExactMxProjectionBackend();

/**
 * Native vendor MXFP4 / FP8 block-scale matmul.
 * FAIL CLOSED: Apple MPP MX·E8M0 / FP8 dequant is not a documented exact
 * integer match for BTX Lever-B M11×2^{e}, e∈{0..3}. Always returns false;
 * never sets native_*_qualified.
 */
[[nodiscard]] bool TryLaunchNativeMxfp4ProjectedRightLT(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m, std::vector<int32_t>& out,
    LtMetalMxProvenance* provenance = nullptr);

[[nodiscard]] bool ComputeDigestsOnlyLTMetal(const CBlockHeader& tmpl, uint32_t n,
                                             const uint64_t* nonces, size_t count,
                                             std::vector<matmul::v4::lt::DigestOnlyResultLT>& out);

/** Optional MX provenance for the most recent ComputeDigestsOnlyLTMetal call
 *  that used Metal projection (defaults remain fail-closed). */
[[nodiscard]] LtMetalMxProvenance LtLastMetalMxProvenance();

/** True iff most recent LaunchGemmS8S8 used MPP TensorOps (not ALU). */
[[nodiscard]] bool LtLastS8S8UsedTensorOps();

} // namespace matmul_v4::metal

#endif // BITCOIN_METAL_MATMUL_V4_LT_ACCEL_H
