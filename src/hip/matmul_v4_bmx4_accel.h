// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HIP_MATMUL_V4_BMX4_ACCEL_H
#define BITCOIN_HIP_MATMUL_V4_BMX4_ACCEL_H

#include <uint256.h>

#include <cstdint>
#include <vector>

class CBlockHeader;

// ===========================================================================
// AMD ROCm/HIP BMX4-C (MatMul v4.2, ENC-BMX4C profile) acceleration backend.
//
// Structural sibling of src/hip/matmul_v4_accel.{h,hip} (the v4.1 ENC-S8
// batched HIP backend): same host/device split (derive operands on the host
// with the SHARED reference routines, run the heavy integer GEMMs on the CDNA
// Matrix Cores, finish the tiny mod-q combine + serialization on host/device
// integer ALUs so the digest is bit-identical to the CPU), same
// memory-adaptive chunking and verify+fallback posture (a separate dispatch
// layer re-verifies this backend's output against the CPU reference and
// falls back to CPU on any mismatch -- this file does not self-verify).
//
// PROFILE. This targets the ENC-BMX4C encoding profile (doc/btx-matmul-v4.2-
// bmx4c-spec.md, CPU reference src/matmul/matmul_v4_bmx4.{h,cpp}), NOT the
// v4.1 ENC-S8 profile the sibling file targets:
//   * operands are dequantized E2M1-mantissa x E8M0-block-scale integers,
//     mu in M11 = {0,+-1,+-2,+-3,+-4,+-6} times a per-32-block power-of-two
//     scale 2^e, e in {0,1,2,3}; |Ahat|,|Bhat| <= E_max = 48 (s8-native);
//   * U, V are scale-free M11 projectors, |.| <= 6;
//   * the combine uses 4 balanced BASE-2^6 digits (base 64, remainder-top
//     rule: 3 masked low digits in [-32,31] plus an unmasked top digit
//     carrying the exact remainder) instead of v4.1's balanced base-2^7.
//
// BIT-EXACTNESS CONTRACT (design spec §5 / C-1'): this backend MUST reproduce,
// byte for byte, the digest and sketch payload produced by the CPU reference
// matmul::v4::bmx4::ComputeDigestBMX4C for the same (header, n). Every
// intermediate value on the committed path is an exactly held integer:
// INT8xINT8->INT32 exact MFMA GEMMs for P = U*Ahat and Q_i = Bhat_i*V, exact
// base-64 remainder-top digit decomposition, 16 limb-pair exact s8xs8->s32
// MFMA GEMMs, and an exact mod-q = 2^61-1 fold on the integer ALU. There is
// NO floating point and NO rounding anywhere on the committed path.
//
// TWO COMPUTE TIERS (doc/btx-matmul-v4.2-bmx4c-spec.md §5.2 K'-table; see the
// .hip file's SelectComputeTier for the concrete gate):
//   (a) NATIVE CDNA4 MXFP4 (E8M0-scaled block FP4, e.g. MI355X gfx950). The
//       sampler's accepted nibble IS the element's OCP E2M1 bit pattern
//       (matmul_v4_bmx4.cpp SampleMantissaNibble), so mu/e can be packed
//       directly into the OCP MX block-scaled layout (32-element blocks, one
//       E8M0 scale byte per block) with ZERO reinterpretation and dispatched
//       through hipBLASLt's block-scaled FP4 GEMM (HIPBLASLT_R_4F_E2M1
//       element / HIPBLASLT_R_8F_E8M0 (or rocBLAS's equivalent
//       rocblas_datatype_f4_r / block-scale extension) on gfx942/gfx950) or a
//       future v_mfma_scale_*_f8f6f4-class compiler intrinsic. ELIGIBLE ONLY
//       if the device has been qualification-PROVEN (design spec §5.3 M-t24
//       vectors) to hold a true >= 24-bit exact accumulator on that datapath
//       (BMX4C_NATIVE_PATH_PROVEN_T = 24, consensus::Params
//       nMatMulBMX4CMinProvenAccumulatorBits); an unproven or t~14 device MUST
//       fall to tier (b).
//   (b) INT8 MFMA FALLBACK: pre-shift dequant (Ahat = mu*2^e, exact integer
//       shift, computed once on the host) then run the WHOLE object as ONE
//       s8xs8->s32 GEMM family at the device's full INT8 rate -- E_max = 48
//       fits s8 natively, so unlike wider alphabets this profile never needs
//       a multi-GEMM slice/promote schedule on the fallback tier.
//
// References (AMD CDNA INT8 GEMM -- same citations as the v4.1 sibling):
//   * AMD Lab Notes, "AMD matrix cores" (GPUOpen); ROCm Blogs "AMD matrix
//     cores" (v_mfma_i32_16x16x16i8); LLVM builtins-amdgcn-mfma.cl;
//     ROCm/amd_matrix_instruction_calculator.
//   * hipBLASLt (ROCm 6.x+) ships block-scaled FP4/FP6/FP8 GEMM support for
//     gfx942 (MI300)/gfx950 (MI350/MI355) under its "OCP microscaling" (MX)
//     data types; rocBLAS documents the analogous INT8 rocblas_gemm_ex path
//     used by tier (b)'s production drop-in. Exact enum names vary by ROCm
//     release and are NOT hard-coded here (no ROCm toolchain is available in
//     this development environment to pin them against a real header) --
//     tier (a) is therefore scaffolding + comments only, gated permanently to
//     "unavailable" (see the .hip file) until it is wired and verified
//     against real headers and real MI300/MI355-class silicon.
//
// UNVERIFIABLE WITHOUT HARDWARE (stated per the task's requirements): kernel
// compiles under a real hipcc/ROCm toolchain; the MFMA intrinsic's per-lane
// operand/accumulator layout against amd_matrix_instruction_calculator on
// real silicon; hipMemGetInfo-driven chunk sizing behavior under real device
// memory pressure; the entire tier (a) native MXFP4 path (no intrinsic
// signature or hipBLASLt MX enum was available to test against); wall-clock
// throughput/tax figures. All of these are exercised only via reasoning
// against the committed CPU reference (src/matmul/matmul_v4_bmx4.{h,cpp}) and
// structural mirroring of the reviewed v4.1 HIP backend
// (src/hip/matmul_v4_accel.hip), never against real hardware.
// ===========================================================================

namespace matmul_v4::bmx4::hip {

/** True iff this translation unit was compiled with the real HIP backend
 *  (BTX_ENABLE_HIP). When false, ComputeDigestsBMX4CAccel always returns
 *  false and the caller must use the CPU reference
 *  (matmul::v4::bmx4::ComputeDigestBMX4C). */
[[nodiscard]] bool Bmx4CHipBackendCompiled();

/** Largest per-chunk nonce window, mirroring matmul_v4::hip::kMaxBatchedWindow
 *  for cross-backend/cross-profile consistency. Like the v4.1 sibling, this
 *  backend primarily sizes its chunk from ACTUAL free device memory
 *  (hipMemGetInfo) at call time; this constant is applied only as a final
 *  sanity clamp. */
inline constexpr uint32_t kMaxBatchedWindowBMX4C = 256;

/** GPU miner: compute the ENC-BMX4C consensus digest and sketch payload for
 *  every header in `headers` at dimension `n` on an AMD CDNA/RDNA device,
 *  bit-identically to matmul::v4::bmx4::ComputeDigestBMX4C(headers[i], n, ...)
 *  for each i.
 *
 *  Mirrors the I1' template-amortization the CPU reference's seed derivation
 *  already implies (matmul_v4_bmx4.cpp: DeriveOperandSeedBMX4C(A, ...) and
 *  DeriveProjectorSeedsBMX4C both key off matmul::v4::ComputeTemplateHash,
 *  identically to the v4.1 profile): Ahat, U, V and P = U*Ahat are
 *  TEMPLATE-scoped -- derived and computed ONCE from headers[0] -- and every
 *  header in `headers` MUST project onto that same template hash or this call
 *  fails closed (returns false, outputs cleared) with NO partial results,
 *  exactly like matmul_v4::hip::ComputeDigestsBatchedAccel. Only the
 *  nonce-fresh Bhat_i = ExpandOperandB(seed_b_i, n), the per-header
 *  Q_i = Bhat_i*V, and the per-header combine + digest are marginal cost.
 *
 *  Compute path (see the .hip file for the concrete kernels): P = U*Ahat and
 *  every Q_i = Bhat_i*V are exact INT8xINT8->INT32 GEMMs (tier (a) native
 *  block-scaled MXFP4 if the device is t=24-proven eligible, else tier (b)
 *  INT8 MFMA on the pre-shifted dequantized operands -- see the header
 *  comment above). The combine folds P and Qstack = [Q_1|...|Q_count] through
 *  the SAME 4-limb balanced BASE-2^6 remainder-top tensor path as the CPU's
 *  matmul::v4::bmx4::ComputeCombineLimbTensorBMX4C (16 limb-pair exact
 *  s8xs8->s32 MFMA GEMMs + an O(m*count*m) mod-q = 2^61-1 recombine on the
 *  integer ALU), which that CPU function's own header comment proves
 *  byte-identical to the direct combine matmul::v4::ComputeCombineModQ that
 *  matmul::v4::bmx4::ComputeDigestBMX4C actually invokes -- so this backend's
 *  output is byte-identical to the per-header CPU digest by transitivity.
 *
 *  Returns false iff (n, matmul::v4::kTileB) is invalid for ENC-BMX4C
 *  (matmul::v4::bmx4::ValidateDimsBMX4C: n%32==0, the base-2^6 combine bound,
 *  and the shared v4 dimension bound), `rounds == 0`, `headers` is empty, any
 *  header's matmul::v4::ComputeTemplateHash disagrees with headers[0]'s, or
 *  any HIP runtime/device error occurred (no usable GPU, allocation failure,
 *  kernel launch failure, ...). On false, `digests_out`/`payloads_out` are
 *  cleared and the caller MUST fall back to the CPU reference
 *  (matmul::v4::bmx4::ComputeDigestBMX4C per header). `rounds` is accepted
 *  for API symmetry with the CPU/v4.1-accel entry points and validated as > 0
 *  (the miner runs no Freivalds rounds). */
[[nodiscard]] bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                            std::vector<uint256>& digests_out,
                                            std::vector<std::vector<unsigned char>>& payloads_out);

} // namespace matmul_v4::bmx4::hip

// ---------------------------------------------------------------------------
// Dispatcher-integration adapter.
//
// src/matmul/accel_v4.h (the existing MatMul v4 GPU-mining dispatch/
// integration layer -- NOT part of this task's editable surface, read-only
// context here) declares and calls the ENC-BMX4C HIP entry point as
// `matmul_v4::hip::ComputeDigestsBMX4CAccel` (mirroring
// `matmul_v4::cuda::ComputeDigestsBMX4CAccel` / `matmul_v4::metal::
// ComputeDigestsBMX4CAccel`), and `matmul/accel_v4_stub.cpp` already provides
// a weak `matmul_v4::hip::ComputeDigestsBMX4CAccel` stub returning false so
// the dispatcher always links. That is a DIFFERENT namespace from this file's
// task-specified entry point above (`matmul_v4::bmx4::hip`). Both surfaces
// are provided here so (a) the exact fixed signature this task specifies
// exists and holds the real implementation, and (b) the pre-existing
// dispatcher contract is actually satisfied -- a strong definition of
// `matmul_v4::hip::ComputeDigestsBMX4CAccel`, compiled in whenever this file
// is, that simply forwards to (a). Without this adapter the dispatcher would
// keep resolving to the always-false weak stub and this backend would never
// be reachable from SolveMatMulV4 / ComputeDigestsBMX4CDispatched, whatever
// this file's own namespace looks like in isolation.
namespace matmul_v4::hip {
[[nodiscard]] bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                            std::vector<uint256>& digests_out,
                                            std::vector<std::vector<unsigned char>>& payloads_out);
} // namespace matmul_v4::hip

#endif // BITCOIN_HIP_MATMUL_V4_BMX4_ACCEL_H
