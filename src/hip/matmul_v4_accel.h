// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HIP_MATMUL_V4_ACCEL_H
#define BITCOIN_HIP_MATMUL_V4_ACCEL_H

#include <uint256.h>

#include <cstdint>
#include <vector>

class CBlockHeader;

// AMD ROCm/HIP acceleration backend for the MatMul v4 proof-of-work digest
// (design spec btx-matmul-v4-design-spec.md §A.4/§E). This is the AMD CDNA
// (MFMA) analogue of the NVIDIA path; it targets AMD Instinct accelerators
// (gfx908 MI100, gfx90a MI200, gfx942 MI300) whose Matrix Cores expose the
// integer MFMA instructions v_mfma_i32_*_i8 (INT8 inputs, exact INT32
// accumulate).
//
// BIT-EXACTNESS CONTRACT (§B.6): this backend MUST reproduce, byte for byte,
// the digest and sketch payload produced by the CPU reference
// matmul_v4::ComputeDigest for the same (header, n, rounds). The compute path
// is pure integer arithmetic end to end -- INT8xINT8->INT32 exact MFMA GEMMs
// for U*A and B*V, then an exact mod-q = 2^61-1 combine for (U*A)*(B*V) on the
// integer ALU. There is NO floating-point or approximate step anywhere. A
// separate dispatch layer is expected to verify this backend's output against
// the CPU reference and fall back to CPU on any mismatch.

namespace matmul_v4 {
namespace hip {

/** True iff this translation unit was compiled with the real HIP backend
 *  (BTX_ENABLE_HIP). When false, ComputeDigestAccel always returns false and
 *  the caller must use the CPU reference. */
[[nodiscard]] bool HipBackendCompiled();

/** GPU miner: compute the consensus digest and sketch payload for `header` at
 *  dimension `n` on an AMD CDNA device, bit-identically to
 *  matmul_v4::ComputeDigest (§A.4 Solve, §E.1 payload).
 *
 *  Derives sigma, the nonce-fresh operand B, and the template-scoped operand A
 *  and projectors U,V (§A.2 v4.1/I1') exactly as
 *  the CPU reference (balanced-s8; the operands are guaranteed equal to CPU
 *  because they are expanded with the shared matmul::v4 host routines), forms
 *  the two exact INT8->INT32 GEMMs P = U*A (m x n) and Q = B*V (n x m) on the
 *  MFMA matrix cores, combines Chat = P*Q reduced mod q = 2^61-1 in exact int64
 *  (never materializing the n x n product C -- this is the §E.3 optimal
 *  (U*A)(B*V) path), serializes Chat to `payload_out`, and sets
 *  `digest_out = H(sigma || Chat)`.
 *
 *  Returns false iff (n, kTileB=4) is invalid for v4, `rounds == 0`, or any HIP
 *  runtime/device error occurred (no usable GPU, allocation failure, ...). On
 *  false the outputs are unspecified and the caller MUST fall back to CPU.
 *  `rounds` is accepted for API symmetry with the CPU entry point and validated
 *  as > 0 (the miner runs no Freivalds). */
[[nodiscard]] bool ComputeDigestAccel(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                                      uint256& digest_out, std::vector<unsigned char>& payload_out);

/** Largest window processed as ONE device chunk, mirroring the CUDA backend's
 *  kMaxBatchedWindow (matmul_v4_accel.h) for cross-backend consistency. Unlike
 *  CUDA, this backend does NOT rely on this constant to size its buffers: it
 *  queries hipMemGetInfo at call time and picks a chunk size that fits the
 *  ACTUAL free device memory (see the .hip file's chunking comment), because
 *  AMD Instinct parts span a much wider memory range (gfx908 MI100 32 GiB ..
 *  gfx90a MI200 64/128 GiB .. gfx942 MI300 192 GiB) than one fixed constant
 *  could serve well. kMaxBatchedWindow is still applied as a final sanity
 *  clamp on the memory-derived chunk size. */
inline constexpr uint32_t kMaxBatchedWindow = 256;

/** Batched GPU miner (design spec §K.2b, Appendix C-13). The CPU reference this
 *  mirrors bit-for-bit is matmul::v4::BatchedSketchMiner::Mine
 *  (src/matmul/matmul_v4_batch.h/.cpp):
 *
 *   - TEMPLATE-scoped, ONCE per window: A, U, V are expanded and P = U*A
 *     (m x n, exact INT32) is computed on the MFMA cores exactly once, keyed by
 *     ComputeTemplateHash(headers[0]). Every header in `headers` MUST project
 *     onto that same template hash -- checked up front for EVERY header, fail
 *     closed (return false, outputs cleared) on the first mismatch, exactly
 *     like BatchedSketchMiner::Mine. This is a hard consensus-safety gate: a
 *     stale/mismatched template combined with a fresh header would silently
 *     produce a digest that is NOT that header's consensus digest.
 *   - Per header i: sigma_i = DeriveSigma(headers[i]) and the nonce-fresh
 *     operand B_i are derived/expanded on the host with the shared
 *     matmul::v4 routines (guaranteed byte-identical to CPU); Q_i = B_i*V is
 *     computed on device and written directly into column block i of the
 *     horizontal stack Qstack (n x count*m).
 *   - ONE LARGE DENSE COMBINE: Chat_wide = P * Qstack (m x count*m) via the
 *     4-limb balanced base-2^7 tensor path (Appendix C-13; the on-device
 *     digit-for-digit port of matmul::v4::ComputeCombineLimbTensorStacked) --
 *     16 exact INT8->INT32 MFMA GEMMs of shape m x count*m x n plus one
 *     integer-ALU mod-q = 2^61-1 recombine. Column block i of the result is
 *     byte-identical to the single-nonce combine (every output entry depends
 *     only on its own P row and Qstack column; the limb decomposition is
 *     entrywise; see the .hip file for the full byte-exactness argument).
 *   - Per header i (host): payload_i = SerializeSketch(Chat_i);
 *     digest_i = ComputeSketchDigest(sigma_i, payload_i). `digests_out[i]` /
 *     `payloads_out[i]` are byte-identical to
 *     matmul_v4::ComputeDigest(headers[i], n, rounds).
 *
 *  The window may be processed internally in device-memory-bounded chunks
 *  (see the .hip file for the per-chunk footprint formula and the default/max
 *  chunk sizing); this is purely an implementation/throughput detail and does
 *  not change any output byte -- chunk boundaries never cross a nonce, so
 *  every column block is still evaluated against the complete P/limb planes.
 *
 *  Returns false iff (n, kTileB=4) is invalid for v4, `rounds == 0`, `headers`
 *  is empty, any header's template hash disagrees with headers[0]'s, or any
 *  HIP/device error occurred. On false, `digests_out`/`payloads_out` are
 *  cleared and the caller MUST fall back to the CPU batched miner
 *  (matmul::v4::BatchedSketchMiner) or the per-nonce reference.
 *  `rounds` is accepted for API symmetry with the per-nonce entry point and
 *  validated as > 0 (the miner runs no Freivalds). */
[[nodiscard]] bool ComputeDigestsBatchedAccel(
    const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
    std::vector<uint256>& digests_out,
    std::vector<std::vector<unsigned char>>& payloads_out);

} // namespace hip
} // namespace matmul_v4

#endif // BITCOIN_HIP_MATMUL_V4_ACCEL_H
