// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_EXACT_FLOAT_H
#define BTX_MATMUL_MATMUL_V4_EXACT_FLOAT_H

#include <matmul/matmul_v4.h>

#include <cstdint>
#include <vector>

// EXACT-INTEGER-ON-FLOAT (Ozaki-scheme) miner path — CPU reference.
//
// Purpose (doc/btx-matmul-v4-exact-int-on-float.md; roadmap §3.3 Option C /
// backlog O-1): reproduce the v4 consensus objects — the exact int32 product
// C = A*B and the committed sketch Chat = U*C*V over q = 2^61-1 — BYTE-FOR-BYTE
// on hardware whose only fast matmul unit is a *floating-point* tensor core
// (FP8 E4M3 / FP4 E2M1: Trainium-class parts, and any future part that keeps
// only FP fast paths). This is a MINER-SIDE computation variant, not a
// consensus change: the Freivalds verifier (§D.3/§E.2) checks the committed
// integers and never the method, so a miner that produces the identical bytes
// via FP slices is indistinguishable from one using INT8 IMMA.
//
// THE DETERMINISM THEOREM this file is built on (the no-rounding-ever rule):
//
//     A floating-point operation whose true mathematical result is exactly
//     representable in the destination format returns that result IDENTICALLY
//     under ANY rounding mode (nearest-even, truncation, a vendor's
//     undocumented tensor-core rounder), with or without FMA fusion, in any
//     accumulation order, and regardless of subnormal flushing (no value on
//     this path is subnormal) — because there is nothing to round.
//
// Cross-vendor FP divergence (non-IEEE tensor-core accumulators, unknown
// rounding, order-dependence — Fasi/Higham/Mikaitis/Pranesh, PeerJ CS 7:e330)
// is therefore neutralized NOT by pinning a schedule but by arranging that
// every FP value on the committed path is an exactly representable integer at
// every step:
//
//   1. SLICING. Every s8 value on the pipeline (operands in [-125,125]; C-13
//      limb digits in [-64,63]) is split into k base-2^w digit slices — k-1
//      balanced digits in [-2^(w-1), 2^(w-1)-1] plus a top slice carrying the
//      exact remainder in [-2^(w-1), +2^(w-1)] — every slice of magnitude
//      <= 2^(w-1), an exactly representable integer of the FP format
//      (FP8 E4M3, p=4 significand bits: w=4, k=2, slices in [-8,8];
//      FP4 E2M1, p=2: w=3, k=3, slices in [-4,4] — all inside the exact E2M1
//      value set {0,±0.5,±1,±1.5,±2,±3,±4,±6}; 5, the first integer E2M1
//      cannot hold, never occurs).
//   2. EXACT PRODUCTS. Every slice x slice product has magnitude
//      <= 2^(2(w-1)) (64 / 16) and at most 2p significant bits — exact in the
//      MMA unit's product datapath and in any accumulator format used here.
//   3. BLOCKED, PROVABLY-EXACT ACCUMULATION (the real teeth). Native FP
//      accumulation is NEVER trusted beyond the provably exact range: an FP
//      accumulator rounds the moment a partial sum exceeds 2^t, where t is the
//      accumulator's significand width — and t VARIES BY VENDOR and can be far
//      below FP32's 24 (some Hopper FP8 MMA paths retain ~14 bits; the
//      DeepSeek-V3 report, arXiv:2412.19437 §3.3.2, promotes to FP32 registers
//      every 128 elements for exactly this reason). The inner dimension is
//      therefore processed in blocks of K' = 2^(t - 2(w-1)) terms, so every
//      partial sum inside a block is an integer of magnitude <= K'*2^(2(w-1))
//      = 2^t — exactly representable, hence order- and rounder-independent by
//      the theorem above. At each block boundary the exact block sum is
//      EXTRACTED (an exact FP->int conversion of an integer < 2^31) and
//      PROMOTED into a wide integer accumulator on the int ALU/VPU; the FP
//      accumulator is reset. Cross-block accumulation is pure exact integer
//      arithmetic. No FP operation on the committed path ever rounds.
//   4. EXACT RECOMBINATION. The k^2 slice-pair GEMM results S_st (exact int32)
//      recompose the exact integer product termwise via integer shifts:
//      sum_st 2^(w(s+t)) * S_st — on the int ALU, never in FP. The recombined
//      integers are the SAME integers the s8xs8->s32 path produces, so every
//      downstream consensus object (C, P, Q, the C-13 limb fold, Chat,
//      SerializeSketch, the digest) is byte-identical by construction.
//
// Because exactness — not a pinned schedule — is what delivers determinism,
// the FP format, slice width w, block length K', and accumulation order are
// MINER-LOCAL choices, constrained only by the inequalities above. Two miners
// on different FP hardware (or one on INT8 IMMA) produce the identical
// committed bytes. Consequently NOTHING here is consensus: the verifier,
// digest, q, n, b, kTileB, kCombineLimbs and every golden vector are untouched.
//
// ELIGIBILITY / FAILURE BOUNDARY (mirrors the roadmap §4.1 TPU-v4 rule): a
// platform whose FP unit rounds *within* the used bounded regime (accumulator
// narrower than its assumed t, inexact products, no way to extract exact block
// partial sums) computes wrong integers -> a wrong digest -> the accel_v4
// verify+fallback dispatcher rejects it and the determinism self-test fails
// LOUDLY. Such a device is ineligible for this path, exactly as a
// 2^24-mantissa-bounded MXU is ineligible for the INT8 path. This is the same
// generalized invariant as backlog C-1: "exact-integer accumulation on the
// committed path — whether the unit is nominally integer or float."
//
// This CPU reference validates the DECOMPOSITION/RECOMBINATION pipeline (slice
// planes, blocked accumulation schedule, shifts, limb fold) with exact integer
// arithmetic mirroring the device schedule step for step; the claim that an FP
// unit reproduces each step bit-exactly is the documented numerical proof
// above (per-op enumeration in doc/btx-matmul-v4-exact-int-on-float.md §3),
// not a CPU float simulation. Literature: Ozaki/Ogita/Oishi/Rump, Numer.
// Algorithms 59(1):95-118 (2012); Ootomo/Ozaki/Yokota, IJHPCA 2024
// (arXiv:2306.11975, ozIMMU); Uchino/Ozaki/Imamura, IJHPCA 2025
// (arXiv:2409.13313); arXiv:2504.08009 (Ozaki II); arXiv:2508.00441 (FP64 via
// FP8 tensor cores); OCP OFP8 v1.0 (E4M3) and OCP MX v1.0 (E2M1).

namespace matmul::v4::exact_float {

using int8_field::Fq;

/** Target floating-point tensor-core element formats. */
enum class FpFormat : uint8_t {
    FP8_E4M3, // OCP OFP8: 1 sign, 4 exp, 3 mantissa bits (+implicit) -> p=4; max finite 448
    FP4_E2M1, // OCP MX:   1 sign, 2 exp, 1 mantissa bit  (+implicit) -> p=2; max finite 6
};

/** Static slicing parameters for a format. Chosen so every slice digit is an
 *  exactly representable integer of the format and k slices cover the full s8
 *  input range [-128,127] (a superset of the balanced-s8 operand range
 *  [-125,125] and of the C-13 limb-digit range [-64,63]). The first k-1
 *  slices are balanced base-2^w digits in [-2^(w-1), 2^(w-1)-1]; the top
 *  slice carries the exact remainder, provably in [-2^(w-1), +2^(w-1)] for
 *  every s8 input (a pure balanced scheme covers only the ASYMMETRIC range
 *  [-h*(b^k-1)/(b-1), (h-1)*(b^k-1)/(b-1)], e.g. [-136,119] at w=4/k=2 —
 *  missing s8 inputs 120..127). Max slice magnitude is 2^(w-1) either way, so
 *  the slice-pair product bound is 2^(2(w-1)). */
struct SliceScheme {
    uint32_t significand_bits; // p, including the implicit leading bit
    int32_t max_finite;        // largest finite value of the format
    uint32_t slice_bits;       // w: base 2^w digit slices, |slice| <= 2^(w-1)
    uint32_t slice_count;      // k: number of slices (k-1 balanced + remainder top)
};

/** FP8 E4M3: p=4, w=4, k=2 (slices in [-8,8]).
 *  FP4 E2M1: p=2, w=3, k=3 (slices in [-4,4]). */
[[nodiscard]] SliceScheme SchemeFor(FpFormat fmt);

/** Narrowest guaranteed-exact accumulator significand width to assume when a
 *  device's true width is unproven: 14 bits, the measured effective precision
 *  of Hopper-class FP8 tensor-core accumulation (DeepSeek-V3, arXiv:2412.19437
 *  §3.3.2 — the reason it promotes to FP32 every 128 elements). A device that
 *  PROVES a wider exact accumulator (e.g. true FP32 accumulate, t=24) may use
 *  the larger K' — the committed bytes are identical either way. */
inline constexpr uint32_t kConservativeAccumSignificandBits = 14;

/** Full FP32 accumulator significand width (IEEE binary32: 24 incl. implicit). */
inline constexpr uint32_t kFp32AccumSignificandBits = 24;

/** True iff integer `v` is exactly representable in `fmt` (|v| <= max finite
 *  and the odd part of |v| fits in p significand bits). Used by the self-tests
 *  to pin that every slice digit is an exact format value. */
[[nodiscard]] bool IsExactInFormat(int32_t v, FpFormat fmt);

/** Maximum block length K' such that any partial sum of <= K' slice-pair
 *  products is an integer of magnitude <= K' * 2^(2(w-1)) <= 2^t — i.e. every
 *  intermediate value the FP accumulator ever holds is exactly representable
 *  with t significand bits, so accumulation NEVER rounds (the no-rounding-ever
 *  rule). K' = 2^(t - 2(w-1)); returns 0 if t < 2(w-1) (format unusable at
 *  that accumulator width). FP8/w=4: K'=256 at t=14, 2^18 at t=24.
 *  FP4/w=3: K'=1024 at t=14, 2^20 at t=24. At the header-max inner dimension
 *  n = 65535 the promoted integer totals stay < 2^22 (FP8) / 2^20 (FP4). */
[[nodiscard]] uint32_t MaxExactAccumBlock(FpFormat fmt, uint32_t accum_significand_bits);

/** Decompose `count` s8 values into k = slice_count base-2^w digit planes:
 *  vals[idx] == sum_s planes[s][idx] * 2^(w*s), where planes 0..k-2 hold
 *  balanced digits in [-2^(w-1), 2^(w-1)-1] and the top plane holds the exact
 *  remainder in [-2^(w-1), +2^(w-1)]; every slice value is exactly
 *  representable in `fmt` (IsExactInFormat). Structurally the FP analogue of
 *  the C-13 DecomposeLimbPlanes (matmul_v4.cpp) and of the Ozaki-scheme
 *  operand splitting (arXiv:2306.11975 §3). Unique and total for every s8
 *  input; deterministic pure-integer digit extraction. */
[[nodiscard]] std::vector<std::vector<int8_t>> DecomposeSlicePlanes(const int8_t* vals, size_t count,
                                                                    FpFormat fmt);

/** Exact integer GEMM out = A*B via the FP slice path: A is rows x inner, B is
 *  inner x cols, both row-major s8; out is rows x cols exact int32 — the SAME
 *  integers a native s8xs8->s32 GEMM produces (pinned byte-identical by the
 *  unit tests). Evaluates the k^2 slice-pair GEMMs with the blocked
 *  extract-and-promote accumulation schedule (block length K' from
 *  MaxExactAccumBlock(fmt, accum_significand_bits); every in-block partial sum
 *  <= 2^t, promoted exactly into an integer accumulator at each block
 *  boundary), then recombines with exact integer shifts. On device the k^2
 *  slice-pair GEMMs are native FP8/FP4 MMA calls; on this CPU reference each
 *  step is the exact integer the FP unit provably returns. The caller must
 *  respect the §B.4-analogue bound inner * 127^2 < 2^31 (every header n and
 *  every limb-pair GEMM satisfies it) and pass accum_significand_bits >=
 *  2(w-1) so K' >= 1. */
[[nodiscard]] std::vector<int32_t> ExactGemmViaFloatSlices(
    const std::vector<int8_t>& A, const std::vector<int8_t>& B,
    uint32_t rows, uint32_t inner, uint32_t cols, FpFormat fmt,
    uint32_t accum_significand_bits = kConservativeAccumSignificandBits);

/** C = A*B on the FP slice path; BYTE-IDENTICAL to matmul::v4::
 *  ComputeExactProduct(A, B, n) (§A.3/§B.4 semantics, same row-major exact
 *  int32 layout). A/B are n*n row-major balanced-s8. */
[[nodiscard]] std::vector<int32_t> ComputeExactProductViaFloat(
    const std::vector<int8_t>& A, const std::vector<int8_t>& B, uint32_t n, FpFormat fmt,
    uint32_t accum_significand_bits = kConservativeAccumSignificandBits);

/** P = U*A on the FP slice path; BYTE-IDENTICAL to ComputeProjectedLeft. */
[[nodiscard]] std::vector<int32_t> ComputeProjectedLeftViaFloat(
    const std::vector<int8_t>& U, const std::vector<int8_t>& A, uint32_t n, uint32_t m, FpFormat fmt,
    uint32_t accum_significand_bits = kConservativeAccumSignificandBits);

/** Q = B*V on the FP slice path; BYTE-IDENTICAL to ComputeProjectedRight. */
[[nodiscard]] std::vector<int32_t> ComputeProjectedRightViaFloat(
    const std::vector<int8_t>& B, const std::vector<int8_t>& V, uint32_t n, uint32_t m, FpFormat fmt,
    uint32_t accum_significand_bits = kConservativeAccumSignificandBits);

/** Combine stage on the FP slice path: the C-13 limb-tensor combine (4 balanced
 *  base-2^7 limb planes of P and Q, 16 limb-pair GEMMs, shifted mod-q fold)
 *  with each limb-pair s8 GEMM evaluated via ExactGemmViaFloatSlices instead of
 *  a native s8xs8->s32 MMA. The limb-pair products S_ij are the identical
 *  exact integers, and the fold is the identical FqFromSigned/FqMul/FqAdd
 *  sequence, so the result is BYTE-IDENTICAL to ComputeCombineLimbTensor(P, Q,
 *  n, m) — and therefore to ComputeCombineModQ (Appendix C-13 equivalence).
 *  Requires CheckCombineLimbBound(n) like the integer path. (A miner may
 *  equivalently flatten the two-level limb+slice split into a single wider
 *  balanced base-2^w decomposition of P/Q — 7 digits at w=4 — with the same
 *  committed integers; this reference keeps the two-level form to reuse the
 *  pinned C-13 fold.) */
[[nodiscard]] std::vector<Fq> ComputeCombineLimbTensorViaFloat(
    const std::vector<int32_t>& P, const std::vector<int32_t>& Q, uint32_t n, uint32_t m, FpFormat fmt,
    uint32_t accum_significand_bits = kConservativeAccumSignificandBits);

/** Full optimal-miner sketch on the FP slice path: Chat = (U*A)(B*V) mod q with
 *  P, Q, and the combine all evaluated via FP slices. BYTE-IDENTICAL to
 *  ComputeSketchOptimal(U, A, B, V, n, m) and hence to
 *  ComputeSketch(U, ComputeExactProduct(A, B), V, n, m) — the committed object
 *  (§E.1) is unchanged down to SerializeSketch bytes and the digest. This is
 *  what an FP-only backend's ComputeDigestAccel would compute per nonce (the
 *  batched §K.2b form stacks Q columns exactly as the INT8 backends do). */
[[nodiscard]] std::vector<Fq> ComputeSketchViaFloat(
    const std::vector<int8_t>& U, const std::vector<int8_t>& A,
    const std::vector<int8_t>& B, const std::vector<int8_t>& V,
    uint32_t n, uint32_t m, FpFormat fmt,
    uint32_t accum_significand_bits = kConservativeAccumSignificandBits);

} // namespace matmul::v4::exact_float

#endif // BTX_MATMUL_MATMUL_V4_EXACT_FLOAT_H
