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
 *  Derives sigma and the nonce-fresh operands A,B and projectors U,V exactly as
 *  the CPU reference (balanced-s8; the operands are guaranteed equal to CPU
 *  because they are expanded with the shared matmul::v4 host routines), forms
 *  the two exact INT8->INT32 GEMMs P = U*A (m x n) and Q = B*V (n x m) on the
 *  MFMA matrix cores, combines Chat = P*Q reduced mod q = 2^61-1 in exact int64
 *  (never materializing the n x n product C -- this is the §E.3 optimal
 *  (U*A)(B*V) path), serializes Chat to `payload_out`, and sets
 *  `digest_out = H(sigma || Chat)`.
 *
 *  Returns false iff (n, kTileB=8) is invalid for v4, `rounds == 0`, or any HIP
 *  runtime/device error occurred (no usable GPU, allocation failure, ...). On
 *  false the outputs are unspecified and the caller MUST fall back to CPU.
 *  `rounds` is accepted for API symmetry with the CPU entry point and validated
 *  as > 0 (the miner runs no Freivalds). */
[[nodiscard]] bool ComputeDigestAccel(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                                      uint256& digest_out, std::vector<unsigned char>& payload_out);

} // namespace hip
} // namespace matmul_v4

#endif // BITCOIN_HIP_MATMUL_V4_ACCEL_H
