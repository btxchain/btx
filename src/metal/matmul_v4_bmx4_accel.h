// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_METAL_MATMUL_V4_BMX4_ACCEL_H
#define BITCOIN_METAL_MATMUL_V4_BMX4_ACCEL_H

#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

class CBlockHeader;

// Apple Metal backend for the MatMul v4.2 ENC-BMX4C (BMX4-C) miner
// (doc/btx-matmul-v4.2-bmx4c-spec.md; structural template: the v4.1 backend
// in metal/matmul_v4_accel.h).
//
// Apple silicon has no MXFP4 tensor unit, so BMX4-C on Apple runs on the
// spec's INT8 fallback rung (§5.2 row "INT8 s8xs8->s32"): the committed
// object is evaluated as an EXACT-INTEGER matmul over the HOST-dequantized
// operands. The host expands the M11 mantissa and E8M0 scale planes and
// applies the scale as an exact power-of-two shift (|Ahat|,|Bhat| <= E_max =
// 48 <= 127, s8-native; matmul::v4::bmx4::ExpandOperandA/B), expands the
// scale-free M11 projectors (|U|,|V| <= 6), and the GPU runs
//   P = U*Ahat and Qvert = [Bhat_1; ...; Bhat_Q]*V as exact INT8 -> INT32
//   integer GEMMs, then the combine Chat = P*Q mod q (q = 2^61-1) as the 16
//   balanced base-2^6 remainder-top limb-pair GEMMs (spec §3, C-13') folded
//   with exact 64-bit integer mod-q arithmetic.
// Serialization and the digest H(sigma || Chat) run on the HOST via the exact
// matmul::v4 consensus routines. No floating point exists anywhere on this
// path (C-1': no operation on the committed path may ever round); results are
// required to be bit-identical to the CPU reference
// matmul::v4::bmx4::ComputeDigestBMX4C, and the implementation self-tests
// against that reference on first use, refusing to run (returning false) on
// any device that cannot reproduce it exactly.
//
// GEMM tiers (identical to the v4.1 backend, each gated by its own one-time
// bit-exactness self-test): the portable integer-ALU threadgroup-tile kernel
// on every Metal GPU family (pre-M5), and Metal 4 mpp::tensor_ops::matmul2d
// (INT8 in / INT32 accumulate -- exact by construction) on M5-class GPU
// neural accelerators.
//
// The non-Apple / non-Metal build links matmul_v4_bmx4_accel_stub.cpp, where
// every entry point reports unavailable, so callers always fall back to the
// CPU reference.

namespace matmul_v4::bmx4::metal {

struct AccelProbe {
    bool available{false};
    // "alu" (portable integer-ALU kernels, any Metal GPU) or "tensor_ops"
    // (Metal 4 mpp::tensor_ops::matmul2d on M5-class GPU neural accelerators).
    std::string gemm_path;
    std::string device_name;
    std::string reason;
};

/** Probe Metal BMX4-C acceleration: initializes the Metal context (device,
 *  queue, pipelines) and runs the one-time batched bit-exactness self-test vs
 *  the CPU reference matmul::v4::bmx4::ComputeDigestBMX4C. Cheap after the
 *  first call. */
AccelProbe ProbeAcceleration();

/** Batched miner backend entry point for ENC-BMX4C: compute the BMX4-C
 *  consensus digests and sketch payloads for a whole nonce WINDOW of headers
 *  sharing one template. digests_out[i] / payloads_out[i] are byte-identical
 *  to matmul::v4::bmx4::ComputeDigestBMX4C(headers[i], n, ...).
 *
 *  Amortization structure (mirrors the v4.1 batched backend, invariant I1'):
 *  template-scoped Ahat, U, V are expanded (and Ahat dequantized) ONCE on the
 *  host, P = U*Ahat is ONE device INT8->INT32 GEMM (cached across calls by
 *  template hash) split on device into 4 balanced base-2^6 remainder-top
 *  digit planes; per nonce only Bhat is expanded/dequantized (host) and
 *  Qvert = [Bhat_1; ...; Bhat_Q]*V runs as ONE stacked device GEMM per
 *  window; the per-nonce combines fuse into ONE LARGE DENSE GEMM
 *  P * [Q_1 | ... | Q_Q] evaluated as the 16 base-2^6 limb-pair INT8->INT32
 *  GEMMs (the entrywise digit split replicates the CPU
 *  DecomposeLimbPlanesBMX4C digit-for-digit) plus the shifted mod-q recombine
 *  Chat = sum_ij 2^(6(i+j)) * S_ij in exact 64-bit integer ALU arithmetic --
 *  byte-identical to the reference ComputeCombineModQ because the digit
 *  identity x = sum_l 64^l d_l is exact and canonical residues are unique.
 *  Operand derivation, dequantization, serialization, and digest run on the
 *  HOST via the exact matmul_v4_bmx4 / matmul_v4 consensus routines; there is
 *  no floating point anywhere.
 *
 *  The GEMMs use the portable integer-ALU kernels on every Metal GPU family
 *  (pre-M5) and Metal 4 mpp::tensor_ops::matmul2d on M5-class GPU neural
 *  accelerators when available -- both exact INT8 -> INT32, both gated by a
 *  one-time batched bit-exactness self-test against ComputeDigestBMX4C.
 *  Windows are processed in device-sized chunks (default 8 nonces; override
 *  with BTX_MATMUL_V4_BMX4_METAL_BATCH, clamped to
 *  [1, matmul::v4::kMaxMinerBatch] and to the device's buffer/working-set
 *  limits).
 *
 *  Returns false -- never a wrong or approximate answer -- iff `headers` is
 *  empty, (n, kTileB=4) is invalid for ENC-BMX4C (ValidateDimsBMX4C: v4
 *  bounds plus n % 32 == 0 and 288*n <= 2^23-1), `rounds` is 0, ANY header
 *  does not project onto the shared ComputeTemplateHash (fail closed: a stale
 *  template must never be combined with fresh nonces), Metal is unavailable,
 *  the self-test failed on this device, or any GPU submission fails; the
 *  dispatch layer then falls back to the CPU path. */
[[nodiscard]] bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
    std::vector<uint256>& digests_out, std::vector<std::vector<unsigned char>>& payloads_out);

} // namespace matmul_v4::bmx4::metal

#endif // BITCOIN_METAL_MATMUL_V4_BMX4_ACCEL_H
