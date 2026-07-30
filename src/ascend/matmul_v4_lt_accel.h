// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_ASCEND_MATMUL_V4_LT_ACCEL_H
#define BITCOIN_ASCEND_MATMUL_V4_LT_ACCEL_H

#include <matmul/matmul_v4_lt.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class CBlockHeader;

// ---------------------------------------------------------------------------
// Huawei Ascend 950 (昇腾) ExactGemm host backend for MatMul v4.4 ENC-DR-LT.
//
// Grounded in CANN ≥ 9.1 / Ascend 950PR·DT (dav-3510) aclnn / asc-devkit notes:
//   aclnnQuantMatmulV5 with x1/x2=INT8, x2Scale=FLOAT32(1), and out=INT32 has
//   documented raw out=x1@x2 semantics; all scale inputs are ignored.
//   aclnnCalculateMatmulWeightSizeV2 + aclnnTransMatmulWeight supplies the
//   required AI-processor-affine NZ weight layout. The runtime retains device
//   buffers, page-locked staging, a stream, and the largest workspace across calls.
// `used_cube_path` is set ONLY after process-local ExactGemmS8S8 self-qual
// (odd axes + max-|entry| corners) and a native QuantMatmulV5 launch that
// matched byte-for-byte. Ordinary aclnnMm/Matmul is deliberately not used:
// released public dtype contracts do not document it as INT8->INT32.
//
// Lever-B MX twin:
//   Exact MX B̂·V is the four Cube ExactGemm scale partition (e∈{0..3}, shift,
//   sum), self-qualified byte-identical to ComputeProjectedRightMxBlockScaleLT.
//   MatExpand Extract remains host ExpandOperandBMatExpandMxComponents (Cube
//   ExactGemm inject for G*W / (G*W)*H). FoldInt32ToEmax48 in self-qual fillers
//   is GEMM shape noise only — not consensus Extract. native_mx_qualified stays
//   false unless a CANN FP8/MX op proves bit-identity (none admitted today).
// Without CANN: stub declines. Public activation remains inert (INT32_MAX).
// ---------------------------------------------------------------------------

namespace matmul_v4::ascend {

/** Per-call / last-success provenance for Ascend LT digests. Fields are true
 *  only when the successful path actually used that property; stub and any
 *  decline clear them. `native_mx_qualified` is never true without a proven
 *  CANN FP8/MX kernel vs the CPU oracle (currently always false). */
struct LtAscendDigestProvenance {
    bool used_cube_path{false};
    bool exact_mx_scale_partitioned{false};
    bool native_mx_qualified{false};
};

/** Initializes the backend-owned AscendCL runtime once and returns the actual
 *  SoC string reported by aclrtGetSocName. False is fail-closed; no environment
 *  or guessed-device fallback is used. */
[[nodiscard]] bool GetAscendRuntimeSocName(std::string& out);

/** True iff this build has CANN, an NPU is visible, and process-local
 *  ExactGemmS8S8 self-qualification (incl. odd-accumulator / max-|entry|
 *  probes) passed on the Cube/aclnn path. */
[[nodiscard]] bool IsAscendExactGemmAvailable();

/** True iff Cube ExactGemm is available AND the four-pass MX B̂·V path has
 *  self-qualified byte-identical to ComputeProjectedRightMxBlockScaleLT. */
[[nodiscard]] bool IsAscendExactMxProjectionAvailable();

/** Host ExactGemmS8S8 via Ascend Cube/aclnn when available. On success `out`
 *  is byte-identical to matmul::v4::lt::ExactGemmS8S8. If `used_cube_path` is
 *  non-null it is set true ONLY when the Cube/aclnn datapath executed after
 *  self-qual; otherwise false. Returns false → caller MUST use CPU ExactGemm. */
[[nodiscard]] bool ExactGemmS8S8Ascend(const std::vector<int8_t>& left,
                                       const std::vector<int8_t>& right,
                                       uint32_t rows, uint32_t inner, uint32_t cols,
                                       std::vector<int32_t>& out,
                                       bool* used_cube_path = nullptr);

/** Bounded exact S32×S8 implemented as four radix-256 S8 Cube GEMMs. */
[[nodiscard]] bool ExactGemmS32S8Ascend(const std::vector<int32_t>& left,
                                        const std::vector<int8_t>& right,
                                        uint32_t rows, uint32_t inner, uint32_t cols,
                                        std::vector<int32_t>& out,
                                        bool* used_cube_path = nullptr);

/** ExactGemmBackend::S8S8Fn / S32S8Fn adapters — require used_cube_path=true. */
[[nodiscard]] bool TryLaunchLtCubeGemmS8S8(const std::vector<int8_t>& left,
                                           const std::vector<int8_t>& right,
                                           uint32_t rows, uint32_t inner, uint32_t cols,
                                           std::vector<int32_t>& out);
[[nodiscard]] bool TryLaunchLtCubeGemmS32S8(const std::vector<int32_t>& left,
                                            const std::vector<int8_t>& right,
                                            uint32_t rows, uint32_t inner, uint32_t cols,
                                            std::vector<int32_t>& out);

/** Exact MX scale-partitioned B̂·V via four Cube ExactGemm passes (e∈{0..3}).
 *  On success `out` is byte-identical to ComputeProjectedRightMxBlockScaleLT.
 *  Sets provenance flags when non-null. Fail-closed without Cube + MX self-qual. */
[[nodiscard]] bool ComputeProjectedRightMxBlockScaleLTAscend(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m, std::vector<int32_t>& out,
    LtAscendDigestProvenance* provenance = nullptr);

/** ExactMxProjectionBackend::Fn adapter — Cube four-pass MX B̂·V.
 *  Sets MxLaneProvenance::exact_mx_scale_partitioned on success; never sets
 *  native_mxfp4_* / native_fp8_* without a proven CANN native path. */
[[nodiscard]] bool TryLaunchLtCubeMxProjectRight(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m, std::vector<int32_t>& out,
    matmul::v4::lt::MxLaneProvenance* provenance);

/** Digest-only ENC-DR-LT entry. Declines unless Cube ExactGemm and the exact
 *  MX scale-partitioned projection are available. Injects Cube S8S8/S32S8 into
 *  MatExpand and runs Cube four-pass MX B̂·V. Digests are byte-identical to
 *  ComputeDigestBMX4CLT. Optional `provenance` reports the successful lane. */
[[nodiscard]] bool ComputeDigestsOnlyLTAscend(
    const CBlockHeader& tmpl, uint32_t n, const uint64_t* nonces, size_t count,
    std::vector<matmul::v4::lt::DigestOnlyResultLT>& out,
    LtAscendDigestProvenance* provenance = nullptr);

/** Last successful ComputeDigestsOnlyLTAscend / MX projection provenance
 *  (process-local). Cleared on decline. */
[[nodiscard]] LtAscendDigestProvenance LastAscendDigestProvenance();

} // namespace matmul_v4::ascend

#endif // BITCOIN_ASCEND_MATMUL_V4_LT_ACCEL_H
