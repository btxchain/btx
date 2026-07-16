// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_BMX4_H
#define BTX_MATMUL_MATMUL_V4_BMX4_H

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <vector>

class CBlockHeader;

// ---------------------------------------------------------------------------
// ENC-BMX4C committed-object encoding profile (MatMul v4.2 / BMX4-C).
//
// This is the CPU integer REFERENCE for the frontier-native ENC-BMX4C profile
// pinned by doc/btx-matmul-v4.2-consolidated-design.md. It is the bit-exact
// ground truth every backend / golden vector mirrors byte-for-byte.
//
// It changes ONLY the operand ENCODING (design §8.1 "versioned encoding
// profile"); the invariant verification core is reused UNCHANGED from
// matmul::v4: the field q = 2^61-1 (int8_field.h), the wide counter-mode
// SHA-256 XOF, the projections P = U*A / Q = B*V, the direct mod-q combine,
// SerializeSketch / ParseSketch / ComputeSketchDigest, and the O(n^2)
// SketchFreivalds verifier. VerifySketch_BMX4C dequantizes the (mantissa,
// scale) operand streams into exact integers and calls matmul::v4::
// SketchFreivalds with no changes -- the verifier is compute-path-agnostic by
// construction (design §3).
//
// Differences from the v4.1 ENC-S8 profile (namespace matmul::v4):
//   * operands are E2M1-integer mantissas mu in M11 = {0,+-1,+-2,+-3,+-4,+-6}
//     times a per-32-block power-of-two scale 2^e, e in {0,1,2,3} (E8M0, S=3);
//     dequantized |Ahat| <= E_max = 48 (still <= 127, so INT8-native);
//   * U, V are i.i.d. over M11, SCALE-FREE (|.| <= 6);
//   * the combine uses 4 balanced base-2^6 digits (base 64, digits [-32,31]
//     with the remainder-carrying top rule) instead of base-2^7;
//   * V4.2 domain tags for the seed derivations.
//
// EVERYTHING here is exact integer arithmetic. NO float appears on the
// committed path (design §4 C-1').
// ---------------------------------------------------------------------------

namespace matmul::v4::bmx4 {

using int8_field::Fq;

// --- Pinned encoding constants (design §2.1, §2.4, §5.2) --------------------

/** The E2M1-integer mantissa alphabet M11 = {0, +-1, +-2, +-3, +-4, +-6}
 *  (design §2.1). Exactly the integer-valued subset of OCP-MX FP4 E2M1;
 *  +-5, +-0.5, +-1.5 are structurally absent. 11 symbols. */
inline constexpr std::array<int8_t, 11> kAlphabetM11 =
    {0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
inline constexpr uint32_t kAlphabetSize = 11;

/** Largest mantissa magnitude in M11 (the value 6). */
inline constexpr int32_t kMantissaMaxAbs = 6;

/** E8M0 block-scale discipline (design §2.1): one shared power-of-two scale
 *  2^e per L = 32-element block along the contraction dimension K, with the
 *  exponent e in {0..S}, S = 3. */
inline constexpr uint32_t kBlockLen = 32;   // OCP block length L
inline constexpr uint32_t kScaleS = 3;      // S = E_max exponent range
inline constexpr uint32_t kNumScaleCodes = 4; // e in {0,1,2,3}

/** Dequantized operand magnitude bound E_max = M_max * 2^S = 6*8 = 48
 *  (design §2.4). 48 <= 127 keeps every INT8 part 1-GEMM native. */
inline constexpr int32_t kEmax = kMantissaMaxAbs << kScaleS; // 48
static_assert(kEmax == 48, "E_max must be 6*2^3 = 48");
static_assert(kEmax <= 127, "E_max must fit s8 for the 1-GEMM INT8 embedding");

/** Per-MAC magnitude of the base product C = Ahat*Bhat: E_max^2 = 2304
 *  (design §2.4). |C| <= 2304*n < 2^24 at n = 4096. */
inline constexpr int32_t kBaseProductPerMac = kEmax * kEmax; // 2304

/** Per-MAC magnitude of the projections P = U*Ahat, Q = Bhat*V:
 *  6 * 48 = 288 (design §2.2/§2.4, the scale-free M11 U/V). |P|,|Q| <= 288*n. */
inline constexpr int32_t kProjPerMac = kMantissaMaxAbs * kEmax; // 288

// --- Combine: 4 balanced base-2^6 digits, remainder-top rule (design §5.2) --

/** Combine limb count and base: 4 balanced base-2^6 digits (base 64). The low
 *  3 digits are in [-32, 31]; the top digit carries the exact remainder in
 *  [-32, +32] (the remainder-top rule), making the decomposition TOTAL and
 *  UNIQUE for every |x| < 64^4/2 = 2^23 (design §5.2). Each digit plane is a
 *  valid s8 tensor operand (|digit| <= 32). */
inline constexpr uint32_t kCombineLimbs = 4;
inline constexpr int32_t kCombineLimbBase = 64;      // base 2^6
inline constexpr int32_t kCombineDigitLow = -32;     // low-3-digit min
inline constexpr int32_t kCombineDigitHigh = 31;     // low-3-digit max
static_assert(kCombineLimbBase == 64, "base-2^6 combine pins base 64");

/** CORRECTED asymmetric-extreme constant (design §5.2): a PURE balanced
 *  base-2^6 scheme (all 4 digits in [-32,31]) covers positives only up to
 *  31*(64^4-1)/63 = 8,255,455 (the redesign doc's 8,255,527 is off by 72),
 *  i.e. 288*n total-decomposes only to n <= 28,664. This is MOOT under the
 *  remainder-top rule the reference adopts, which reaches the full |x| < 2^23
 *  window -- but the constant is pinned so the correction is machine-checked. */
inline constexpr int64_t kCombinePureBalancedPositiveExtreme = 8'255'455;
static_assert(kCombinePureBalancedPositiveExtreme ==
                  31LL * (64LL * 64 * 64 * 64 - 1) / 63,
              "pure balanced base-2^6 positive extreme = 31*(64^4-1)/63");

/** The remainder-top total-decomposition bound: |x| <= 2^23 - 1 = 8,388,607.
 *  CheckCombineLimbBound_BMX4C pins 288*n <= 2^23 - 1 (design §5.2 "the
 *  CheckCombineLimbBound successor pins 288*n <= 2^23-1"), i.e. n <= 29,127 --
 *  the whole 4096..8192 window with ~3.5x margin. */
inline constexpr int64_t kCombineMaxAbs = (static_cast<int64_t>(1) << 23) - 1; // 8,388,607

/** Per-MAC bound of a base-2^6 limb-pair GEMM: 32*32 = 1024, so |S_ij| <=
 *  1024*n = 2^22 at n = 4096 (design §2.4) -- sub-2^24, runnable on any
 *  proven-t=24 or true-int32 unit. */
inline constexpr int32_t kCombineLimbPairPerMac = 32 * 32; // 1024

// --- Sampler primitives (design §2.3) --------------------------------------

/** Map one 4-bit nibble to an M11 mantissa by the pinned E2M1 bijection
 *  (design §2.3): bit3 = sign, bits2..1 = exp, bit0 = mantissa; decode the FP4
 *  E2M1 value and ACCEPT iff it is a non-negative-zero integer. The 5 rejected
 *  codes are exactly {+-0.5, +-1.5, -0} (nibbles 1,3,8,9,11). Acceptance
 *  11/16. Returns the mantissa on accept; sets `accepted=false` on a hole. */
[[nodiscard]] int8_t SampleMantissaNibble(uint8_t nibble, bool& accepted);

/** Deterministically expand `count` M11 mantissas from a seed via a wide
 *  counter-mode SHA-256 XOF (mantissa-plane domain byte 'm'): one 4-bit nibble
 *  per element in stream order (low nibble of each keystream byte first, then
 *  high nibble), E2M1-rejection-sampled into M11. Exact-integer, byte-
 *  reproducible, PQ-safe. This is the mantissa plane for A, B, U, and V. */
void ExpandMantissaStream(const uint256& seed, size_t count, int8_t* out);

/** Deterministically expand `count` E8M0 exponents e in {0,1,2,3} from a seed
 *  via a wide counter-mode SHA-256 XOF (scale-plane domain byte 'e'): 2 bits
 *  per code, 4 codes per keystream byte from the LSB up, rejection-free. This
 *  is the scale plane for A and B (U/V have none). */
void ExpandScaleStream(const uint256& seed, size_t count, uint8_t* out);

// --- Seed derivation (design §2.3, V4.2 domain tags) -----------------------

/** V4.2 seed derivations (design §2.3), mirroring the v4.1 I1'/§H.4 scoping:
 *   seed_A = SHA256("BTX_MATMUL_SEED_V42"     || template_hash    || 0x41) TMPL
 *   seed_B = SHA256("BTX_MATMUL_SEED_V42"     || full_header_hash || 0x42) NONCE
 *   seed_U = SHA256("BTX_MATMUL_V42_SKETCH_U" || template_hash)           TMPL
 *   seed_V = SHA256("BTX_MATMUL_V42_SKETCH_V" || template_hash)           TMPL
 *  A/U/V are template-scoped; B is nonce-fresh (its mantissa AND scale planes,
 *  design condition #6). sigma = SHA256d(header) is reused UNCHANGED. */
[[nodiscard]] uint256 DeriveOperandSeedBMX4C(const CBlockHeader& header, Operand which);
[[nodiscard]] std::pair<uint256, uint256> DeriveProjectorSeedsBMX4C(const CBlockHeader& header);

// --- Operand / projector expansion + dequant (design §2.1) -----------------

/** Expand + dequantize operand A: Ahat[i][k] = mu_A[i][k] * 2^{e_A(i,k/32)},
 *  n*n row-major exact integers with |Ahat| <= 48 (fits int8). The scale
 *  block runs along the contraction dim (columns of A): scale plane is
 *  n x (n/32) row-major. Requires n % 32 == 0. */
[[nodiscard]] std::vector<int8_t> ExpandOperandA(const uint256& seed, uint32_t n);

/** Expand + dequantize operand B: Bhat[k][j] = mu_B[k][j] * 2^{e_B(k/32,j)},
 *  n*n row-major exact integers with |Bhat| <= 48. The scale block runs along
 *  the contraction dim (rows of B): scale plane is (n/32) x n row-major. */
[[nodiscard]] std::vector<int8_t> ExpandOperandB(const uint256& seed, uint32_t n);

/** Expand a scale-free M11 projector (U is m*n, V is n*m; design §2.2). */
[[nodiscard]] std::vector<int8_t> ExpandProjectorBMX4C(const uint256& seed,
                                                       uint32_t rows, uint32_t cols);

// --- Combine: base-2^6 limb tensor (design §5) -----------------------------

/** True iff the 4-digit base-2^6 remainder-top decomposition is total for
 *  every P/Q entry at dimension n: 288*n <= 2^23-1 (design §5.2). Holds for
 *  all n <= 29,127. */
[[nodiscard]] bool CheckCombineLimbBoundBMX4C(uint32_t n);

/** Base-2^6 limb-tensor combine (design §5): decompose P (m*n) and Q (n*m)
 *  entrywise into 4 balanced base-64 digits (remainder-top), run the 16
 *  limb-pair m*m*n exact s8xs8->s32 GEMMs, and recombine
 *      Chat = sum_ij 2^{6(i+j)} * S_ij  (mod q).
 *  BYTE-IDENTICAL to matmul::v4::ComputeCombineModQ(P, Q, n, m): the digit
 *  identity x = sum_l 64^l d_l is exact, so the shifted mod-q fold reproduces
 *  the canonical sum_k P[a][k]*Q[k][c] mod q. This is the CPU reference for the
 *  GPU tensor-core combine. */
[[nodiscard]] std::vector<Fq> ComputeCombineLimbTensorBMX4C(const std::vector<int32_t>& P,
                                                            const std::vector<int32_t>& Q,
                                                            uint32_t n, uint32_t m);

// --- Digest + verify (mirrors the pow_v4 contract) -------------------------

/** Validate (n, b=kTileB) for ENC-BMX4C: the v4.1 ValidateDims checks PLUS
 *  n % 32 == 0 (block scales) and CheckCombineLimbBoundBMX4C(n). Returns
 *  m = n/b on success. */
[[nodiscard]] bool ValidateDimsBMX4C(uint32_t n, uint32_t b, uint32_t& m_out);

/** Miner: derive the ENC-BMX4C consensus digest and sketch payload for
 *  `header` at dimension `n`. Derives sigma (UNCHANGED SHA256d(header)), the
 *  template-scoped Ahat / U / V and nonce-fresh Bhat, evaluates the sketch
 *  Chat = (U*Ahat)(Bhat*V) over q (byte-identical to projecting the exact
 *  integer product C = Ahat*Bhat), serializes to `payload_out`, and sets
 *  `digest_out = H(sigma || Chat)`. Returns false iff (n, kTileB) is invalid
 *  for ENC-BMX4C. Pure integer arithmetic; no float. */
[[nodiscard]] bool ComputeDigestBMX4C(const CBlockHeader& header, uint32_t n,
                                      uint256& digest_out,
                                      std::vector<unsigned char>& payload_out);

/** Verifier: O(n^2) ENC-BMX4C consensus check. Regenerates the (mu, scale)
 *  streams, dequantizes Ahat/Bhat (exact integers <= 48, fit int8) and the
 *  M11 U/V, recomputes the digest from `payload`, and runs `rounds`
 *  matmul::v4::SketchFreivalds rounds over q against the parsed sketch -- the
 *  verifier is reused UNCHANGED. Returns true iff every round matches AND the
 *  recomputed digest equals `header.matmul_digest`. `digest_out` receives the
 *  recomputed digest. */
[[nodiscard]] bool VerifySketchBMX4C(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                                     const std::vector<unsigned char>& payload,
                                     uint256& digest_out);

} // namespace matmul::v4::bmx4

#endif // BTX_MATMUL_MATMUL_V4_BMX4_H
