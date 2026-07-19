// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HIP_MATMUL_V4_LT_ACCEL_H
#define BITCOIN_HIP_MATMUL_V4_LT_ACCEL_H

#include <matmul/matmul_v4_lt.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

// ---------------------------------------------------------------------------
// AMD ROCm/HIP backend for the MatMul v4.4 ENC-DR-LT ("MatExpand") mining
// surface (src/matmul/matmul_v4_lt.h). Structural sibling of
// hip/matmul_v4_bmx4_accel.{h,hip}, retargeted to the LT profile: dense
// exact-integer MatExpand operands (ExpandOperandAMatExpand /
// ExpandOperandBMatExpand) instead of a SHA XOF, and the ENC-DR deep-m tile
// b = kTileBLT = 2 (m = n/2).
//
// Same posture as the CUDA LT backend (cuda/matmul_v4_lt_accel.cu, read that
// file's header comment for the full reasoning): this TU ships genuine,
// self-tested HIP kernels that reproduce matmul::v4::lt::ExactGemmS8S8 /
// ExactGemmS32S8 bit-for-bit (the only dense tensor-shaped primitives
// MatExpand's public surface exposes), gated by a one-time device-vs-host
// bit-exactness self-test, but the digest computation itself runs through
// the host-exact matmul::v4::lt::WindowSketchMinerLT pipeline so every
// returned digest is byte-identical to matmul::v4::lt::ComputeDigestBMX4CLT
// by construction -- with zero risk of a from-scratch device re-derivation
// of the per-nonce header-binding rule silently diverging from consensus.
//
// The non-HIP build links matmul_v4_lt_accel_stub.cpp, where every entry
// point reports unavailable, so callers always fall back to the CPU/host
// reference.
// ---------------------------------------------------------------------------

namespace matmul_v4::hip {

/** True iff this build was compiled with HIP (BTX_ENABLE_HIP), a usable
 *  AMD GPU is present, and the one-time device-GEMM bit-exactness self-test
 *  has not permanently failed. ComputeDigestsOnlyLTHip is bit-exact
 *  regardless of this flag (it always runs the host-exact reference
 *  pipeline when it returns true at all -- see the .hip file). */
[[nodiscard]] bool IsMatMulLTHipAvailable();

/** Digest-only ENC-DR-LT mining entry, matching the CUDA/Metal LT backends'
 *  contract exactly: `out[i]` mirrors matmul::v4::lt::DigestOnlyResultLT for
 *  `nonces[i]`, with `digest` byte-identical to
 *  matmul::v4::lt::ComputeDigestBMX4CLT for the corresponding header.
 *  `target_match` is always false (no target is supplied by this
 *  signature). Returns false only on a structural failure (`n` invalid for
 *  ENC-DR-LT, `tmpl` does not admit a valid MatExpand window, or
 *  `nonces`/`count` is empty); `out` is cleared on false. */
[[nodiscard]] bool ComputeDigestsOnlyLTHip(const CBlockHeader& tmpl, uint32_t n,
                                          const uint64_t* nonces, size_t count,
                                          std::vector<matmul::v4::lt::DigestOnlyResultLT>& out);

} // namespace matmul_v4::hip

#endif // BITCOIN_HIP_MATMUL_V4_LT_ACCEL_H
