// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_ACCEL_H
#define BITCOIN_CUDA_MATMUL_V4_ACCEL_H

#include <uint256.h>

#include <cstdint>
#include <vector>

class CBlockHeader;

// NVIDIA INT8 tensor-core backend for the MatMul v4 proof-of-work (design spec
// btx-matmul-v4-design-spec.md §A/§B/§E). This is a thin, pure-C++ host surface:
// the implementation lives in matmul_v4_accel.cu (compiled by nvcc) and is
// replaced by matmul_v4_accel_stub.cpp when BTX_ENABLE_CUDA_EXPERIMENTAL is OFF,
// so the tree always builds without a CUDA toolkit.
//
// CONTRACT (bit-exact with matmul_v4::ComputeDigest / pow_v4.cpp): the dispatch
// layer runs this, then verifies `digest_out` (and `payload_out`) against the
// CPU reference and FALLS BACK to the CPU path on any mismatch. Correctness is
// therefore consensus-critical: the accelerated path MUST reproduce the CPU
// digest byte-for-byte or return false. There is NO floating point anywhere on
// this path -- INT8->INT32 accumulation is exact and order-independent (§B.6)
// and the final m x m combine reproduces int8_field.h FqReduce bit-for-bit.

namespace matmul_v4::cuda {

/** Reproduce matmul_v4::ComputeDigest on NVIDIA INT8 tensor cores.
 *
 *  Derives sigma, the nonce-fresh balanced-s8 operand B, and the template-
 *  scoped operand A and projectors U,V (§A.2 v4.1/I1')
 *  EXACTLY as matmul_v4.cpp does (it reuses those host routines, so the
 *  operands are byte-identical to the CPU), evaluates the §E.3 optimal sketch
 *  Chat = (U*A)(B*V) mod q -- the two INT8->INT32 GEMMs on tensor cores, the
 *  final m x m combine reduced mod q = 2^61-1 in the integer ALU -- serializes
 *  Chat and sets `digest_out = H(sigma || Chat)`.
 *
 *  Returns false (so the caller uses the CPU path) iff (n, kTileB=4) is invalid
 *  for v4, `rounds` is 0 (matching the CPU ComputeDigest validity gate), or any
 *  CUDA / cuBLASLt error occurs. On success `payload_out` holds the serialized
 *  m x m sketch (8*m^2 bytes) and `digest_out` the consensus digest. This
 *  routine does NOT check the difficulty target. */
[[nodiscard]] bool ComputeDigestAccel(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                                      uint256& digest_out, std::vector<unsigned char>& payload_out);

/** Suggested nonce-window size Q for ComputeDigestsBatchedAccel. Device memory
 *  per in-flight nonce is ~76 MiB at n=4096 (b=4, m=1024) -- see the buffer
 *  budget table in matmul_v4_accel.cu -- so Q=64 is ~4.9 GiB: large enough to
 *  keep the stacked combine GEMM (m x Q*m x n = 1024 x 65,536 x 4096) firmly
 *  in the tensor-core-bound regime on H100/B200 while still fitting consumer
 *  parts (RTX 4090/5090), which is exactly the comparison B2g must measure. */
inline constexpr uint32_t kDefaultBatchedWindow = 64;

/** Largest window processed as ONE device chunk (~19.1 GiB of device buffers
 *  at n=4096 -- sized to fill an H100 80 GB / B200 with headroom). Requests
 *  larger than this are transparently processed in internal chunks of this
 *  size, reusing the same device allocations, so any window up to the CPU
 *  miner's kMaxMinerBatch works without over-allocating. */
inline constexpr uint32_t kMaxBatchedWindow = 256;

/** Batched digests for one nonce window sharing a single template (design spec
 *  §K.2b, Appendix C-13) -- the device mirror of
 *  matmul::v4::BatchedSketchMiner::Mine. digests_out[i] and payloads_out[i]
 *  are BYTE-IDENTICAL to matmul_v4::ComputeDigest(headers[i], n, rounds).
 *
 *  Amortization structure (§A.2 v4.1, invariant I1'): the template-scoped
 *  A, U, V are expanded ONCE on the host, the left factor P = U*A is ONE
 *  INT8->INT32 device GEMM per call, and the per-nonce right factors
 *  Q_i = B_i*V run as ONE stacked GEMM [B_1; ...; B_Q] * V per window chunk.
 *  The Q per-nonce combines fuse into ONE LARGE DENSE GEMM
 *  P * [Q_1 | ... | Q_Q] evaluated as the 16 limb-pair INT8 tensor GEMMs of
 *  Appendix C-13 (bit-for-bit the CPU ComputeCombineLimbTensorStacked), with
 *  the shifted mod-q recombine on the integer ALU. Operand derivation,
 *  serialization and digest run on the HOST via the exact matmul_v4 routines.
 *  No floating point anywhere; every device stage is exact integer arithmetic.
 *
 *  Returns false (dispatcher falls back to the CPU reference) iff `headers` is
 *  empty, (n, kTileB=4) is invalid, the combine limb bound fails, `rounds` is
 *  0, ANY header does not project onto the shared ComputeTemplateHash (fail
 *  closed: a stale template must never be combined with fresh nonces), or any
 *  CUDA / cuBLASLt error occurs. BTX_MATMUL_V4_CUDA_GEMM=scalar forces the
 *  exact scalar-GEMM fallback, as in ComputeDigestAccel. */
[[nodiscard]] bool ComputeDigestsBatchedAccel(
    const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
    std::vector<uint256>& digests_out,
    std::vector<std::vector<unsigned char>>& payloads_out);

} // namespace matmul_v4::cuda

#endif // BITCOIN_CUDA_MATMUL_V4_ACCEL_H
