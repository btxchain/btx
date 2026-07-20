// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HIP_MATMUL_V4_LT_ACCEL_H
#define BITCOIN_HIP_MATMUL_V4_LT_ACCEL_H

#include <hip/matmul_v4_lt_mx_native.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_lt_mx_exact.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

// ---------------------------------------------------------------------------
// AMD ROCm/HIP backend for MatMul v4.4 ENC-DR-LT (MatExpand).
//
// Digests are bit-identical to matmul::v4::lt::ComputeDigestBMX4CLT.
// When an AMD GPU is present and the one-time bit-identity self-test passes,
// ComputeDigestsOnlyLTHip runs a persistent device-resident loop
// (MatExpand → Extract → project → combine).
//
// B̂·V default on CDNA4 gfx950 is the oracle-identical exact INT8 MX resident
// path. Native MXFP4/MXFP8 qualification is reported separately and becomes
// mandatory only for explicit BTX_MATMUL_V4_LT_REQUIRE_NATIVE_MX=1 qualification
// runs. Dense dequant remains the fallback via BTX_MATMUL_V4_LT_DENSE_BHAT=1.
//
// Native MXFP4 / FP8 (hipBLASLt block-scale / CDNA4 MFMA scale) may be
// attempted only behind self-qual vs the CPU MX oracle; unqualified attempts
// stay fail-closed and never set native_*_qualified.
//
// s8xs8 prefers the self-qualified rocBLAS/hipBLASLt MFMA lane. On that lane,
// MatExpand's s32xs8 stage is exactly radix-lowered into four INT8 GEMMs and
// combine uses nine exact Karatsuba/base-64 INT8 GEMMs; scalar DeviceGemm*
// remains the fail-closed fallback and is never labeled MFMA. Host ExactGemm
// is the final fallback.
//
// Target arches: gfx942 (MI300), gfx950 (MI350/MI355) via BTX_HIP_ARCHITECTURES.
// Linker stub when BTX_ENABLE_HIP is off.
// ---------------------------------------------------------------------------

namespace matmul_v4::hip {

/** Provenance for the full-header Q* entry. Batch residency fields are true
 *  only when the successful call used that property for every candidate.
 *  `mx` reports MX lane honesty (exact scale-partitioned vs native attempt).
 *  Callers must not infer silicon throughput from DigestOnlyBackendStatus. */
struct LtHipBatchProvenance {
    bool qstar_device_batched{false};
    bool device_w_generation{false};
    bool device_digest{false};
    bool per_nonce_sync_absent{false};
    matmul::v4::lt::MxLaneProvenance mx{};
};

/** True iff HIP is enabled, an AMD GPU is present, and the one-time
 *  device bit-identity self-test passed. */
[[nodiscard]] bool IsMatMulLTHipAvailable();

/** Bit-exact device GEMMs backing MatExpand / projection stages, exported so
 *  a matmul::v4::lt::ExactGemmBackend can point its callbacks at them.
 *  Prefer MFMA library → device ALU → pooled scalar tile. Never label ALU as
 *  MFMA. Stub returns false when BTX_ENABLE_HIP is off. */
[[nodiscard]] bool LaunchGemmS8S8(const std::vector<int8_t>& left,
                                  const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t inner, uint32_t cols,
                                  std::vector<int32_t>& out);
[[nodiscard]] bool LaunchGemmS32S8(const std::vector<int32_t>& left,
                                   const std::vector<int8_t>& right,
                                   uint32_t rows, uint32_t inner, uint32_t cols,
                                   std::vector<int32_t>& out);

/** Host-callable exact MX scale-partitioned B̂·V (device GEMMs when available).
 *  On success `out` is byte-identical to ComputeProjectedRightMxBlockScaleLT
 *  and provenance.exact_mx_scale_partitioned is set (unless a qualified native
 *  path served the call). Suitable for ExactMxProjectionBackend::project_right. */
[[nodiscard]] bool LaunchProjectedRightMx(const std::vector<int8_t>& mu,
                                          const std::vector<uint8_t>& scales,
                                          const std::vector<int8_t>& V, uint32_t n,
                                          uint32_t m, std::vector<int32_t>& out,
                                          matmul::v4::lt::MxLaneProvenance* provenance = nullptr);

/** Digest-only ENC-DR-LT mining entry. Prefers the persistent device-resident
 *  loop; falls back to host ExactGemm on decline. Digests are byte-identical
 *  to ComputeDigestBMX4CLT. */
[[nodiscard]] bool ComputeDigestsOnlyLTHip(const CBlockHeader& tmpl, uint32_t n,
                                          const uint64_t* nonces, size_t count,
                                          std::vector<matmul::v4::lt::DigestOnlyResultLT>& out);

/** Consensus-seed-complete Q* batch entry. Unlike the legacy template+nonce
 *  ABI, each slot carries its own seed_a/seed_b. All headers must have the
 *  same ComputeTemplateHash. The resident HIP path queues the complete batch,
 *  hashes each Chat on device, then performs one digest/status transfer and
 *  one stream synchronization. Callers must require those provenance fields
 *  before treating success as resident mining; backend status alone is not
 *  residency proof. Batches larger than kConsensusQStarMax (512) fail before
 *  device allocation or host fallback. */
[[nodiscard]] bool ComputeDigestsOnlyLTHip(
    const std::vector<CBlockHeader>& headers, uint32_t n,
    std::vector<matmul::v4::lt::DigestOnlyResultLT>& out,
    LtHipBatchProvenance* provenance = nullptr);

/** True iff most recent LaunchGemmS8S8 used hipBLASLt/rocBLAS MFMA. */
[[nodiscard]] bool LtLastS8S8UsedMfma();

/** Latest process-local MX lane snapshot (exact / native attempt / qualified). */
[[nodiscard]] matmul::v4::lt::MxLaneProvenance LtLastMxProvenance();

} // namespace matmul_v4::hip

#endif // BITCOIN_HIP_MATMUL_V4_LT_ACCEL_H
