// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_METAL_MATMUL_V4_ACCEL_H
#define BITCOIN_METAL_MATMUL_V4_ACCEL_H

#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

class CBlockHeader;

// Apple Metal backend for the MatMul v4 miner (design spec §A.4/§E.1).
//
// Computes digest_out = H(sigma || Chat) and the serialized sketch payload
// for `header` at dimension `n`, exactly as matmul_v4::ComputeDigest does on
// the CPU (matmul/pow_v4.cpp), with the two O(n^2 * m)-sized projections
//   UA = U * A   and   BV = B * V
// run on the GPU as exact INT8 -> INT32 integer matmuls and the m x m combine
//   Chat = (UA * BV) mod q,  q = 2^61 - 1
// run in exact 64-bit integer arithmetic on the GPU. No floating point exists
// anywhere on this path (§B.6); results are required to be bit-identical to
// the CPU reference, and the implementation self-tests against the CPU
// reference on first use, refusing to run (returning false) on any device
// that cannot reproduce it exactly.
//
// The non-Apple / non-Metal build links matmul_v4_accel_stub.cpp, where every
// entry point reports unavailable, so callers always fall back to the CPU.

namespace matmul_v4::metal {

struct AccelProbe {
    bool available{false};
    // "alu" (portable integer-ALU kernels, any Metal GPU) or "tensor_ops"
    // (Metal 4 mpp::tensor_ops::matmul2d on M5-class GPU neural accelerators).
    std::string gemm_path;
    std::string device_name;
    std::string reason;
};

/** Probe Metal v4 acceleration: initializes the Metal context (device, queue,
 *  pipelines) and runs the one-time bit-exactness self-test vs the CPU
 *  reference. Cheap after the first call. */
AccelProbe ProbeAcceleration();

/** Miner backend entry point (contract mirrored on the CUDA side): compute
 *  the v4 consensus digest and sketch payload for `header` at dimension `n`.
 *
 *  Returns true only if the GPU produced a payload/digest byte-identical in
 *  derivation to matmul_v4::ComputeDigest (same seeds, same operands, same
 *  canonical F_q words, same serialization, same SHA256d). Returns false --
 *  never a wrong or approximate answer -- when Metal is unavailable, the
 *  device failed the bit-exactness self-test, dimensions are invalid or
 *  exceed device buffer limits, or any GPU submission fails; the dispatch
 *  layer then falls back to the CPU path (and, in DEBUG dispatch builds,
 *  cross-checks GPU output against the CPU digest). */
bool ComputeDigestAccel(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                        uint256& digest_out, std::vector<unsigned char>& payload_out);

/** Batched miner backend entry point (fixed BatchAccelFn contract shared
 *  across all backends, design spec §K.2b / Appendix C-13): compute the v4
 *  consensus digests and sketch payloads for a whole nonce WINDOW of headers
 *  sharing one template. digests_out[i] / payloads_out[i] are byte-identical
 *  to matmul_v4::ComputeDigest(headers[i], n, rounds), i.e. bit-for-bit the
 *  CPU reference matmul::v4::BatchedSketchMiner::Mine.
 *
 *  Amortization structure (§A.2 v4.1, invariant I1'): template-scoped A, U, V
 *  are expanded ONCE on the host, P = U*A is ONE device INT8->INT32 GEMM
 *  (cached across calls by template hash); per nonce only B is expanded
 *  (host) and Q_i = B_i*V runs as ONE stacked device GEMM per window; the per-
 *  nonce combines fuse into ONE LARGE DENSE GEMM P * [Q_1 | ... | Q_Q]
 *  evaluated as the 16 limb-pair INT8->INT32 GEMMs of Appendix C-13 (the
 *  entrywise balanced base-2^7 digit split runs on device, replicating the
 *  CPU ComputeCombineLimbTensorStacked digit-for-digit) plus the shifted
 *  mod-q recombine in exact 64-bit integer ALU arithmetic. Operand
 *  derivation, serialization, and digest run on the HOST via the exact
 *  matmul_v4 consensus routines; there is no floating point anywhere.
 *
 *  The GEMMs use the portable integer-ALU kernels on every Metal GPU family
 *  (pre-M5) and Metal 4 mpp::tensor_ops::matmul2d on M5-class GPU neural
 *  accelerators when available -- both exact INT8 -> INT32, both gated by a
 *  one-time bit-exactness self-test against the CPU batched reference.
 *  Windows are processed in device-sized chunks (default 8 nonces; override
 *  with BTX_MATMUL_V4_METAL_BATCH, clamped to [1, matmul::v4::kMaxMinerBatch]
 *  and to the device's buffer/working-set limits).
 *
 *  Returns false -- never a wrong or approximate answer -- iff `headers` is
 *  empty, (n, kTileB=4) is invalid, the combine limb bound fails, `rounds` is
 *  0, ANY header does not project onto the shared ComputeTemplateHash (fail
 *  closed: a stale template must never be combined with fresh nonces), Metal
 *  is unavailable, the batched self-test failed on this device, or any GPU
 *  submission fails; the dispatch layer then falls back to the CPU path. */
[[nodiscard]] bool ComputeDigestsBatchedAccel(
    const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
    std::vector<uint256>& digests_out,
    std::vector<std::vector<unsigned char>>& payloads_out);

} // namespace matmul_v4::metal

#endif // BITCOIN_METAL_MATMUL_V4_ACCEL_H
