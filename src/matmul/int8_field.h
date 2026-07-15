// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_INT8_FIELD_H
#define BTX_MATMUL_INT8_FIELD_H

#include <cstddef>
#include <cstdint>

class uint256;

// Exact-integer INT8 arithmetic for the MatMul v4 compute path, plus the
// independent Freivalds soundness field F_q with q = 2^61 - 1.
//
// Two number systems live here and MUST NOT be conflated (design spec
// btx-matmul-v4-design-spec.md, §0.7-(2), §B, §D):
//
//   * The COMPUTE field is a small exact-integer INT8 domain: dense
//     pseudorandom s8 operands in the balanced range [-125, 125], multiplied
//     with an exact s8xs8->s32 accumulation, producing an exact INT32 product
//     C = A*B with |C_ij| <= n*125^2 < 2^30 for every header-expressible
//     dimension n <= 65535 (§B.4). There is NO modular reduction on the
//     compute path -- C is a literal integer matrix.
//
//   * The SOUNDNESS field is the independent large Mersenne prime
//     q = 2^61 - 1 (§0.7-(2)/§D.3). Freivalds probes of the (exact-integer)
//     product run over F_q so that any two distinct canonical integer entries
//     -- which differ by |delta| < 2^32 < q -- can never alias, giving
//     per-round error <= 1/q ~ 2^-61. Freivalds MUST NEVER run over the
//     compute field (a small ring), which would collapse soundness to ~2^-8
//     (§D.2).
//
// Everything here is pure integer arithmetic (no floating point anywhere) so
// results are bit-identical across NVIDIA IMMA / AMD MFMA / Apple / AVX-512
// backends and independent of accumulation order (§B.6).

namespace matmul::int8_field {

// ---------------------------------------------------------------------------
// Exact-integer INT8 compute domain (§B.2 candidate (i), balanced s8).
// ---------------------------------------------------------------------------

/** Balanced-s8 canonical magnitude bound: operands live in [-125, 125]
 *  (balanced representative of the p = 251 residue field, §B.4/§G.2). */
inline constexpr int32_t kBalancedBound = 125;

/** Maximum per-element product magnitude, 125^2 = 15,625 (§B.4). */
inline constexpr int32_t kElementSqBound = kBalancedBound * kBalancedBound;

/** Largest dimension expressible in the 16-bit header field `matmul_dim`. */
inline constexpr uint32_t kMaxHeaderDim = 65535;

/** True iff a length-`n` s8 dot product cannot overflow the exact INT32
 *  accumulator under the balanced encoding: |C_ij| <= n*125^2 < 2^30
 *  (§B.4/§0.7-(2)). Every header dimension n <= 65535 satisfies this. */
[[nodiscard]] bool CheckAccumulationBound(uint32_t n);

/** Map one XOF byte to a canonical balanced-s8 element by rejection sampling
 *  (§A.2/§B.2/§B.3): bytes >= 251 are rejected (`accepted=false`); otherwise
 *  the residue r in [0,250] is returned as the balanced representative
 *  r - 125 in [-125, 125]. */
[[nodiscard]] int8_t SampleBalancedS8(uint8_t byte, bool& accepted);

/** Deterministically expand `count` canonical balanced-s8 elements from a
 *  seed via a WIDE counter-mode SHA-256 XOF (§A.2, Appendix C-12): keystream
 *  block j = SHA256(seed_le || 's' || LE64(j)), all 32 bytes rejection-sampled
 *  in stream order (~31.4 accepted elements per compression). Exact-integer,
 *  byte-reproducible, and PQ-safe (SHA-256 only); the accepted-byte order is
 *  the normative element order for every backend.
 *
 *  This replaces the retired per-element oracle (one full SHA-256 per element,
 *  31 of 32 output bytes discarded) which made operand expansion -- not the
 *  INT8 GEMM -- the dominant per-nonce cost (PR #89 review). */
void ExpandBalancedS8Stream(const uint256& seed, size_t count, int8_t* out);

/** Exact s8xs8->s32 dot product of two length-`len` balanced-s8 vectors
 *  (§B.2/§B.6). The caller MUST have established the accumulation bound
 *  (CheckAccumulationBound) so the INT32 accumulator never wraps; the result
 *  is then the exact mathematical integer dot product. */
[[nodiscard]] int32_t ExactDot(const int8_t* a, const int8_t* b, uint32_t len);

// ---------------------------------------------------------------------------
// Independent Freivalds soundness field F_q, q = 2^61 - 1 (§D.3).
// ---------------------------------------------------------------------------

/** Field element type; canonical representatives are in [0, q). */
using Fq = uint64_t;

/** Mersenne prime q = 2^61 - 1 (§0.7-(2), §D.3). */
inline constexpr Fq kFieldPrime = (static_cast<Fq>(1) << 61) - 1;

/** Reduce a full 128-bit product into canonical form mod q via the Mersenne
 *  multiply-and-fold (§D.3: "one 64-bit multiply + fold per MAC"). */
[[nodiscard]] Fq FqReduce(unsigned __int128 x);

[[nodiscard]] Fq FqAdd(Fq a, Fq b);
[[nodiscard]] Fq FqSub(Fq a, Fq b);
[[nodiscard]] Fq FqMul(Fq a, Fq b);
[[nodiscard]] Fq FqNeg(Fq a);

/** Reduce an exact signed INT32 product entry (an entry of C = A*B, §B.4) to
 *  its canonical F_q representative. Because |C_ij| < 2^30 < q the mapping is
 *  injective on canonical entries, which is exactly what makes the q-Freivalds
 *  check sound (§D.3). */
[[nodiscard]] Fq FqFromInt32(int32_t x);

/** General signed-integer lift into F_q. */
[[nodiscard]] Fq FqFromSigned(int64_t x);

/** Deterministically expand `count` uniform F_q elements from a seed via the
 *  same wide counter-mode SHA-256 XOF as ExpandBalancedS8Stream (domain byte
 *  'q'): four LE64 words per compression, each masked to 61 bits and
 *  rejection-sampled (only the value q itself rejects, probability 2^-61).
 *  Used for the nonce-fresh Freivalds challenge vectors (§D.1, invariant I7). */
void ExpandFqStream(const uint256& seed, size_t count, Fq* out);

} // namespace matmul::int8_field

#endif // BTX_MATMUL_INT8_FIELD_H
