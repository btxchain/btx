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

} // namespace matmul_v4::metal

#endif // BITCOIN_METAL_MATMUL_V4_ACCEL_H
