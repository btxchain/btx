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
// This TU ships genuine, self-tested HIP kernels that reproduce
// matmul::v4::lt::ExactGemmS8S8 / ExactGemmS32S8 bit-for-bit (the only dense
// tensor-shaped primitives MatExpand's operand expansion contains). When an
// AMD GPU is present and the one-time device-vs-host bit-exactness self-test
// passes, they are injected as a matmul::v4::lt::ExactGemmBackend into
// WindowSketchMinerLT, so MatExpand's two GEMMs (G*W and (G*W)*H) run on
// device while the projection/combine/serialize/digest stages stay on the
// host-exact consensus path. Every returned digest is therefore byte-
// identical to matmul::v4::lt::ComputeDigestBMX4CLT; if the device is
// unavailable the identical miner runs on CPU ExactGemm* (results tagged
// Fallback). No from-scratch re-derivation of the per-nonce header-binding
// rule exists here, so the device path can never diverge from consensus.
//
// The non-HIP build links matmul_v4_lt_accel_stub.cpp, where every entry
// point reports unavailable, so callers always fall back to the CPU/host
// reference.
// ---------------------------------------------------------------------------

namespace matmul_v4::hip {

/** True iff this build was compiled with HIP (BTX_ENABLE_HIP), a usable
 *  AMD GPU is present, and the one-time device-GEMM bit-exactness self-test
 *  has not permanently failed. When true, ComputeDigestsOnlyLTHip offloads
 *  MatExpand's GEMMs to the device; when false it runs the identical CPU
 *  ExactGemm* path. Either way every digest is bit-exact. */
[[nodiscard]] bool IsMatMulLTHipAvailable();

/** Digest-only ENC-DR-LT mining entry, matching the CUDA/Metal LT backends'
 *  contract exactly: `out[i]` mirrors matmul::v4::lt::DigestOnlyResultLT for
 *  `nonces[i]`, with `digest` byte-identical to
 *  matmul::v4::lt::ComputeDigestBMX4CLT for the corresponding header.
 *  `backend_status` is Ok when the device GEMM path served the window and
 *  Fallback when it ran on CPU ExactGemm* (still bit-exact). `target_match`
 *  is always false (no target is supplied by this signature). Returns false
 *  only on a structural failure (`n` invalid for ENC-DR-LT, `tmpl` does not
 *  admit a valid MatExpand window, or `nonces`/`count` is empty); `out` is
 *  cleared on false. */
[[nodiscard]] bool ComputeDigestsOnlyLTHip(const CBlockHeader& tmpl, uint32_t n,
                                          const uint64_t* nonces, size_t count,
                                          std::vector<matmul::v4::lt::DigestOnlyResultLT>& out);

} // namespace matmul_v4::hip

#endif // BITCOIN_HIP_MATMUL_V4_LT_ACCEL_H
