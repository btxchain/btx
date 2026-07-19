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
// This backend ships exact integer Metal (MSL) compute kernels for
// MatExpand's two dense stages -- int8xint8->int32 (Y = G*W) and
// int32xint8->int32 (B32 = Y*H) -- reproducing matmul::v4::lt::ExactGemmS8S8 /
// ExactGemmS32S8 bit-for-bit with true integer accumulation (no float). The
// kernels are self-tested against those CPU references on first use;
// IsMatMulLTMetalAvailable() returns true only once that self-test passes.
// When available, the kernels are injected as a matmul::v4::lt::ExactGemmBackend
// into matmul::v4::lt::WindowSketchMinerLT, so MatExpand's dense GEMM workload
// runs on device while every downstream projection / combine / serialize /
// digest step stays on the host-exact consensus path -- the returned digest is
// therefore bit-identical to matmul::v4::lt::ComputeDigestBMX4CLT by
// construction. If the device or self-test is unavailable, the entry point
// falls back to the pure-CPU reference pipeline (still bit-exact, tagged
// DigestOnlyBackendStatus::Fallback).
//
// The non-Apple / non-Metal build links matmul_v4_lt_accel_stub.cpp, where
// the entry point reports unavailable, so callers always fall back to the
// CPU reference (matmul::v4::lt::ComputeDigestBMX4CLT /
// matmul::v4::lt::WindowSketchMinerLT).
// ---------------------------------------------------------------------------

namespace matmul_v4::metal {

/** True iff this build was compiled with Metal (BTX_ENABLE_METAL), a Metal
 *  device is present, the MatExpand GEMM pipelines built, and the one-time
 *  bit-exactness self-test against matmul::v4::lt::ExactGemmS8S8 /
 *  ExactGemmS32S8 passed. ComputeDigestsOnlyLTMetal below is bit-exact
 *  regardless: when this returns false it falls back to the host-exact
 *  reference pipeline (see the file header). */
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
