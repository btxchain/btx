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
// Apple Metal backend for the MatMul v4.4 ENC-DR-LT ("MatExpand") mining
// surface (src/matmul/matmul_v4_lt.h). Structural sibling of
// metal/matmul_v4_bmx4_accel.{h,mm}, retargeted to the LT profile (deep-m
// tile b = kTileBLT = 2, dense MatExpand operands instead of a SHA XOF).
//
// Metal kernels are OPTIONAL for this backend's first release (the task
// brief explicitly allows "a stub that calls the CPU LT reference" here):
// this header's single entry point runs the host-exact, template-amortized
// matmul::v4::lt::WindowSketchMinerLT pipeline on Apple builds too, so the
// digest is bit-identical to matmul::v4::lt::ComputeDigestBMX4CLT by
// construction with no GPU risk surface at all. A future revision can splice
// Metal compute (portable integer-ALU kernels, or Metal 4
// mpp::tensor_ops::matmul2d on M5-class GPUs, mirroring
// metal/matmul_v4_bmx4_accel.mm) into the window miner's P/Q stages once that
// class exposes an injectable device backend; see matmul_v4_lt_accel.mm's
// file header for the same reasoning cuda/matmul_v4_lt_accel.cu documents.
//
// The non-Apple / non-Metal build links matmul_v4_lt_accel_stub.cpp, where
// the entry point reports unavailable, so callers always fall back to the
// CPU reference (matmul::v4::lt::ComputeDigestBMX4CLT /
// matmul::v4::lt::WindowSketchMinerLT).
// ---------------------------------------------------------------------------

namespace matmul_v4::metal {

/** True iff this build was compiled with Metal (BTX_ENABLE_METAL) and a
 *  Metal device is present. Always returns a truthful availability signal;
 *  ComputeDigestsOnlyLTMetal below is bit-exact regardless (it always runs
 *  the host-exact reference pipeline -- see the file header). */
[[nodiscard]] bool IsMatMulLTMetalAvailable();

/** Digest-only ENC-DR-LT mining entry, matching the CUDA/HIP LT backends'
 *  contract exactly: `out[i]` mirrors matmul::v4::lt::DigestOnlyResultLT for
 *  `nonces[i]`, with `digest` byte-identical to
 *  matmul::v4::lt::ComputeDigestBMX4CLT for the corresponding header.
 *  `target_match` is always false (no target is supplied by this
 *  signature). Returns false only on a structural failure (`n` invalid for
 *  ENC-DR-LT, `tmpl` does not admit a valid MatExpand window, or
 *  `nonces`/`count` is empty); `out` is cleared on false. */
[[nodiscard]] bool ComputeDigestsOnlyLTMetal(const CBlockHeader& tmpl, uint32_t n,
                                             const uint64_t* nonces, size_t count,
                                             std::vector<matmul::v4::lt::DigestOnlyResultLT>& out);

} // namespace matmul_v4::metal

#endif // BITCOIN_METAL_MATMUL_V4_LT_ACCEL_H
