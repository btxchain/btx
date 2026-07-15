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

} // namespace matmul_v4::cuda

#endif // BITCOIN_CUDA_MATMUL_V4_ACCEL_H
