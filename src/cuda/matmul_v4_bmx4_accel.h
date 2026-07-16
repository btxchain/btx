// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_BMX4_ACCEL_H
#define BITCOIN_CUDA_MATMUL_V4_BMX4_ACCEL_H

#include <uint256.h>

#include <cstdint>
#include <vector>

class CBlockHeader;

// NVIDIA backend for the MatMul v4.2 / ENC-BMX4C encoding profile
// (doc/btx-matmul-v4.2-bmx4c-spec.md; CPU reference matmul/matmul_v4_bmx4.h).
// This is a thin, pure-C++ host surface: the implementation lives in
// matmul_v4_bmx4_accel.cu (compiled by nvcc under BTX_ENABLE_CUDA_EXPERIMENTAL)
// and is replaced by matmul_v4_bmx4_accel_stub.cpp when the option is OFF, so
// the tree always builds without a CUDA toolkit.
//
// CONTRACT (bit-exact with matmul::v4::bmx4::ComputeDigestBMX4C): the dispatch
// layer runs this, then verifies digests/payloads against the CPU reference and
// FALLS BACK to the CPU path on any mismatch (accel_v4.h contract, unchanged by
// the v4.2 profile — spec §0.3). Correctness is therefore consensus-critical:
// the backend MUST reproduce the CPU digest byte-for-byte or return false.
// There is NO rounding anywhere on the committed path (C-1', spec §5.1): every
// device stage either computes exact integers or is gated off.
//
// TWO DEVICE TIERS (selected at runtime, both bit-exact by construction):
//
//  * NATIVE FP4 (Blackwell tcgen05 mxf4, E2M1 elements + E8M0 scales, via
//    cuBLASLt block-scaled matmul, CUDA >= 12.8): the marginal GEMMs P = U*Ahat
//    and Q = Bhat*V run on the MXFP4 tensor units as exponent-split mantissa
//    GEMMs, with the committed E8M0 scale applied as an EXACT power-of-two
//    shift in the int32 recombine. ELIGIBLE ONLY IF the device PROVES a t = 24
//    exact FP32 accumulator via the in-process C-1' qualification vectors
//    (spec §5.2 row 1/2: "t = 24 REQUIRED for the native hardware-scaled
//    path"; BMX4C_NATIVE_PATH_PROVEN_T). Datasheets are never trusted — the
//    Hopper "FP32-accumulate" FP8 path that retained ~14 mantissa bits is the
//    standing precedent (spec §5.1).
//  * INT8 FALLBACK (1 GEMM, full rate — spec §5.2 fallback ladder row
//    "INT8 1-GEMM on pre-shifted operands"): dequantized operands (|.| <= 48
//    <= 127) run the exact IMMA s8xs8->s32 path of the v4.1 backend
//    (matmul_v4_accel.cu), true int32 accumulation, no slicing, no K'.
//
// Both tiers share the base-2^6 limb combine (4 balanced digits in [-32,31]
// plus the remainder-top digit, 16 limb-pair s8 GEMMs, shifted mod-q fold with
// weights 2^(6(i+j)) — the device mirror of
// matmul::v4::bmx4::ComputeCombineLimbTensorBMX4C, byte-identical to the
// reference's direct ComputeCombineModQ). Operand derivation, serialization
// and digest run on the HOST via the exact committed routines.

namespace matmul_v4::bmx4::cuda {

/** Suggested nonce-window size Q for ComputeDigestsBMX4CAccel. Device memory
 *  per in-flight nonce at n = 4096, m = 1024 is ~76 MiB on the INT8 tier
 *  (same budget table as the v4.1 backend) and ~110 MiB on the native FP4
 *  tier (adds the packed E2M1 operand stack and the FP32 GEMM output staging
 *  before promotion) — see the buffer budget comment in
 *  matmul_v4_bmx4_accel.cu. */
inline constexpr uint32_t kDefaultBatchedWindow = 32;

/** Largest window processed as ONE device chunk. Larger requests are
 *  transparently processed in internal chunks of this size, reusing the same
 *  device allocations; per-nonce results are independent, so chunking changes
 *  no byte. */
inline constexpr uint32_t kMaxBatchedWindow = 32;

/** Batched ENC-BMX4C digests for one nonce window sharing a single template.
 *  digests_out[i] / payloads_out[i] are BYTE-IDENTICAL to
 *  matmul::v4::bmx4::ComputeDigestBMX4C(headers[i], n, ...).
 *
 *  Amortization structure (v4.1 I1', unchanged by the profile — spec §1.5):
 *  the template-scoped Ahat, U, V are expanded ONCE on the host, P = U*Ahat is
 *  computed once on the device, and the per-nonce right factors Q_i = Bhat_i*V
 *  run as stacked GEMMs per window chunk; the per-nonce combines fuse into the
 *  16 limb-pair GEMMs of the stacked base-2^6 fold.
 *
 *  Returns false (dispatcher falls back to the CPU reference) iff `headers` is
 *  empty, ValidateDimsBMX4C(n, kTileB) fails (includes n % 32 == 0 and the
 *  288n <= 2^23-1 combine input bound), `rounds` is 0, ANY header does not
 *  project onto the shared ComputeTemplateHash (fail closed: a stale template
 *  must never be combined with fresh nonces), any CUDA / cuBLASLt error
 *  occurs, or BTX_MATMUL_BMX4C_CUDA_PATH forces a tier the device cannot
 *  serve. Tier override: BTX_MATMUL_BMX4C_CUDA_PATH in {fp4, int8, scalar}
 *  ("fp4" still requires the t = 24 qualification to PASS — the C-1' gate can
 *  never be bypassed, only narrowed). */
[[nodiscard]] bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
    std::vector<uint256>& digests_out, std::vector<std::vector<unsigned char>>& payloads_out);

} // namespace matmul_v4::bmx4::cuda

#endif // BITCOIN_CUDA_MATMUL_V4_BMX4_ACCEL_H
