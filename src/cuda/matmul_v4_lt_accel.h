// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_LT_ACCEL_H
#define BITCOIN_CUDA_MATMUL_V4_LT_ACCEL_H

#include <cuda/matmul_v4_lt_mx_native.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_lt_mx_exact.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

// ---------------------------------------------------------------------------
// NVIDIA backend for MatMul v4.4 ENC-DR-LT (MatExpand).
//
// Digests are bit-identical to matmul::v4::lt::ComputeDigestBMX4CLT.
//
// When a CUDA device is present and the one-time bit-identity self-test
// passes, ComputeDigestsOnlyLTCuda runs a persistent device-resident loop:
//   MatExpand (G*W, Y*H) → ExtractDequant → project (Bhat*V) → F_q combine.
//
// B̂·V production default: exact MX scale-partitioned INT8 IMMA/ALU
// (bit-identical to ComputeProjectedRightMxBlockScaleLT). Dense dequant remains
// the fallback. Native MXFP4 / FP8 may run only after self-qual vs the CPU
// oracle (else fail-closed); float accumulate is never labeled ExactGemm.
//
// s8xs8 prefers cuBLASLt IMMA when self-qualified; s32xs8 / IMMA decline use
// scalar DeviceGemm* (never labeled IMMA). Full-header batches generate W and
// SHA256d(Chat) on device and return only digests; Host ExactGemm is the
// fail-closed fallback.
//
// Linker stub when BTX_ENABLE_CUDA is off.
// ---------------------------------------------------------------------------

namespace matmul_v4::cuda {

/** Alias of the shared MX lane honesty bits (report / ExactMxProjectionBackend). */
using LtCudaMxProvenance = matmul::v4::lt::MxLaneProvenance;

/** Provenance for the full-header Q* entry. Every field is true only when the
 *  successful call used that property for every candidate; callers must not
 *  infer silicon throughput from DigestOnlyBackendStatus alone. */
struct LtCudaBatchProvenance {
    bool qstar_device_batched{false};
    bool device_w_generation{false};
    bool device_digest{false};
    bool per_nonce_sync_absent{false};
    matmul::v4::lt::MxLaneProvenance mx{};
};

/** True iff this build was compiled with CUDA (BTX_ENABLE_CUDA_EXPERIMENTAL),
 *  a CUDA device is present, and the one-time device bit-identity self-test
 *  (GEMMs + MX projection + one full device-resident digest vs
 *  ComputeDigestBMX4CLT) has not permanently failed. Callers should treat
 *  "false" only as "this backend cannot help"; ComputeDigestsOnlyLTCuda still
 *  produces bit-exact results via the host ExactGemm fail-closed fallback when
 *  the device path is unavailable (except the ENABLE=OFF stub, which declines). */
[[nodiscard]] bool IsMatMulLTCudaAvailable();

/** Bit-exact device GEMMs backing MatExpand / projection stages, exported so
 *  a matmul::v4::lt::ExactGemmBackend can point its callbacks at them
 *  (signatures match ExactGemmBackend::S8S8Fn / S32S8Fn). Uses the process-
 *  persistent scratch pool (cross-call reuse). Returns false on any CUDA
 *  error so the caller falls back to CPU ExactGemm*. Defined only in the
 *  CUDA build (the stub TU omits them). */
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

/** Alias kept for earlier CUDA call sites / tests. */
[[nodiscard]] inline bool LaunchProjectedRightMxBlockScale(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m, std::vector<int32_t>& out)
{
    return LaunchProjectedRightMx(mu, scales, V, n, m, out, nullptr);
}

/** Digest-only ENC-DR-LT mining entry: mine every nonce in `nonces` against
 *  the shared `tmpl` at dimension `n`. Prefers the persistent device-resident
 *  MatExpand→project→combine loop; falls back to host ExactGemm /
 *  WindowSketchMinerLT on decline. `out[i].digest` is BYTE-IDENTICAL to
 *  matmul::v4::lt::ComputeDigestBMX4CLT for the corresponding header.
 *  `target_match` is always false (no target in this signature).
 *  `backend_status` reports bit-exact execution success, but does not prove a
 *  resident batch: host orchestration may still use successful per-call device
 *  GEMMs. Callers making mining/performance claims must use the full-header
 *  overload and require its provenance fields. Returns false only on structural
 *  failure; on false, `out` is cleared. */
[[nodiscard]] bool ComputeDigestsOnlyLTCuda(const CBlockHeader& tmpl, uint32_t n,
                                            const uint64_t* nonces, size_t count,
                                            std::vector<matmul::v4::lt::DigestOnlyResultLT>& out);

/** Consensus-seeded Q* entry. Unlike the legacy template+nonce ABI, this
 *  preserves every candidate's nonce-bound seed_a/seed_b. A successful CUDA
 *  resident call generates W and SHA256d(Chat) on device, returns only one
 *  32-byte digest per candidate, and has one stream synchronization at the
 *  batch boundary. Host fallback remains bit-exact but reports all provenance
 *  fields false. Every header must have the same ComputeTemplateHash, and the
 *  batch must contain at most kConsensusQStarMax (512) headers; oversized calls
 *  fail before device allocation or host fallback. */
[[nodiscard]] bool ComputeDigestsOnlyLTCuda(
    const std::vector<CBlockHeader>& headers, uint32_t n,
    std::vector<matmul::v4::lt::DigestOnlyResultLT>& out,
    LtCudaBatchProvenance* provenance = nullptr);

/** True iff most recent LaunchGemmS8S8 / BackendGemmS8S8 used cuBLASLt IMMA. */
[[nodiscard]] bool LtLastS8S8UsedImma();

/** Latest process-local MX lane snapshot (exact / native attempt / qualified). */
[[nodiscard]] matmul::v4::lt::MxLaneProvenance LtLastMxProvenance();

/** True after process-local self-test proved device exact MX scale-partitioned
 *  projection byte-identical to ComputeProjectedRightMxBlockScaleLT. */
[[nodiscard]] bool IsLtExactMxScalePartitionedAvailable();

} // namespace matmul_v4::cuda

#endif // BITCOIN_CUDA_MATMUL_V4_LT_ACCEL_H
