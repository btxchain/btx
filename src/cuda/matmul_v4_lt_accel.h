// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_LT_ACCEL_H
#define BITCOIN_CUDA_MATMUL_V4_LT_ACCEL_H

#include <matmul/matmul_v4_lt.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

// ---------------------------------------------------------------------------
// NVIDIA backend for the MatMul v4.4 ENC-DR-LT ("MatExpand") mining surface
// (src/matmul/matmul_v4_lt.h, doc/btx-matmul-v4.4-ai-chip-block-reward-strategy.md).
// Structural sibling of cuda/matmul_v4_bmx4_accel.{h,cu}, retargeted to the
// LT profile: operand A/B come from dense exact-integer MatExpand GEMMs
// (ExpandOperandAMatExpand / ExpandOperandBMatExpand) instead of a SHA XOF,
// and the sketch tile is the deep-m ENC-DR tile b = kTileBLT = 2 (m = n/2).
//
// CONTRACT (mirrors accel_v4.h / the BMX4-C backend exactly): every digest
// this backend reports MUST be bit-identical to the CPU/host reference
// matmul::v4::lt::ComputeDigestBMX4CLT for the same (header, n). This TU
// never trusts its own device arithmetic blindly -- see the .cu file's
// "calibrate, then trust" gate -- and the caller MUST still treat a `false`
// return (or an individual result whose backend_status is Fallback/Error) as
// "use the CPU reference for this nonce", exactly like every other v4.x
// device backend in this tree.
//
// GEMM offload. The two dense primitives matmul::v4::lt::ExactGemmS8S8 /
// ExactGemmS32S8 (P = U*A and, on the fallback ladder, the marginal
// per-nonce Q = B*V) are the only tensor-shaped work MatExpand's public
// surface exposes; this backend supplies bit-exact CUDA equivalents of both
// (plain INT8xINT8->INT32 / INT32xINT8->INT32 tiled kernels, true int32
// accumulation, no slicing needed since |MatExpand output| <= kMatExpandEmax
// = 48 <= 127 is s8-native -- same "single INT8 GEMM, no K'" argument the
// BMX4-C backend's header spells out for E_max = 48). Each is self-tested
// against its CPU twin once per process before ANY result is trusted; on ANY
// mismatch the device GEMM is permanently disabled for the process and every
// call here degrades to the host-exact matmul::v4::lt::WindowSketchMinerLT
// pipeline, mirroring the documented "device buffers reserved for bring-up,
// host-exact pipeline is the normative schedule" posture of
// cuda/matmul_v4_bmx4_context.h.
//
// The non-CUDA build links matmul_v4_lt_accel_stub.cpp, where both entry
// points report unavailable, so callers always fall back to the CPU
// reference (matmul::v4::lt::ComputeDigestBMX4CLT /
// matmul::v4::lt::WindowSketchMinerLT).
// ---------------------------------------------------------------------------

namespace matmul_v4::cuda {

/** True iff this build was compiled with CUDA (BTX_ENABLE_CUDA_EXPERIMENTAL),
 *  a CUDA device is present, and the one-time device-GEMM bit-exactness
 *  self-test has not permanently failed. Callers should treat "false" only
 *  as "this backend cannot help"; ComputeDigestsOnlyLTCuda still always
 *  produces bit-exact results (or returns false) even when the underlying
 *  device GEMM offload is unavailable, because it falls back to the CPU
 *  reference pipeline in that case. */
[[nodiscard]] bool IsMatMulLTCudaAvailable();

/** Digest-only ENC-DR-LT mining entry: mine every nonce in `nonces` against
 *  the shared `tmpl` at dimension `n`. `out[i]` mirrors
 *  matmul::v4::lt::DigestOnlyResultLT for `nonces[i]`: `digest` is
 *  BYTE-IDENTICAL to matmul::v4::lt::ComputeDigestBMX4CLT(header_i, n, ...)
 *  where header_i is `tmpl` with the nonce bound in exactly the way
 *  matmul::v4::lt::WindowSketchMinerLT binds it. `target_match` is always
 *  false here (no target is supplied by this signature -- callers that need
 *  target filtering should compare `out[i].digest` themselves); this is a
 *  pure telemetry field per DigestOnlyResultLT's own contract ("consensus
 *  never sees this"). `backend_status` is Ok when a calibrated device GEMM
 *  path produced the result, Fallback when the host-exact
 *  WindowSketchMinerLT pipeline produced it (still bit-exact, just not
 *  device-accelerated), and this function returns false only on a
 *  structural failure (`n` invalid for ENC-DR-LT, `tmpl` does not admit a
 *  valid MatExpand window, `nonces` is null/empty, or the host reference
 *  itself rejects the template). On false, `out` is cleared. */
[[nodiscard]] bool ComputeDigestsOnlyLTCuda(const CBlockHeader& tmpl, uint32_t n,
                                            const uint64_t* nonces, size_t count,
                                            std::vector<matmul::v4::lt::DigestOnlyResultLT>& out);

} // namespace matmul_v4::cuda

#endif // BITCOIN_CUDA_MATMUL_V4_LT_ACCEL_H
