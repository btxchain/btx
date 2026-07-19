// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_METAL_MATMUL_V4_LT_ACCEL_H
#define BITCOIN_METAL_MATMUL_V4_LT_ACCEL_H

#include <matmul/matmul_v4_lt.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

// ---------------------------------------------------------------------------
// Apple Metal backend for MatMul v4.4 ENC-DR-LT (MatExpand).
//
 // Digests are bit-identical to matmul::v4::lt::ComputeDigestBMX4CLT.
 // When a Metal device is present and the GEMM self-test passes, MatExpand's
 // dense GEMMs run on device via ExactGemmBackend with persistent MTLBuffer
 // scratch reuse (cross-call). Projection / combine / digest remain on the
 // shared host routines for this backend; host ExactGemm /
 // WindowSketchMinerLT is the fail-closed fallback when Metal declines —
 // not a claim that host ExactGemm is the complete accelerator (CUDA/HIP
 // carry the fuller device-resident MatExpand→project→combine loop).
 //
 // Linker stub when Metal is unavailable.
// ---------------------------------------------------------------------------

namespace matmul_v4::metal {

/** True iff Metal is enabled, a device is present, pipelines built, and the
 *  one-time ExactGemm bit-exactness self-test passed. */
[[nodiscard]] bool IsMatMulLTMetalAvailable();

/** Digest-only ENC-DR-LT mining entry. Digests are byte-identical to
 *  ComputeDigestBMX4CLT. Falls back to host ExactGemm when Metal declines. */
[[nodiscard]] bool ComputeDigestsOnlyLTMetal(const CBlockHeader& tmpl, uint32_t n,
                                             const uint64_t* nonces, size_t count,
                                             std::vector<matmul::v4::lt::DigestOnlyResultLT>& out);

} // namespace matmul_v4::metal

#endif // BITCOIN_METAL_MATMUL_V4_LT_ACCEL_H
