// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_FREIVALDS_H
#define BTX_MATMUL_MATMUL_V4_RC_FREIVALDS_H

#include <matmul/matmul_v4_rc_gkr_field.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

// FREIVALDS GEMM VERIFICATION over Goldilocks F = GF(p), p = 2^64 − 2^32 + 1.
//
// Given A (int8, m×k), B (int8, k×n) and a claimed product Y (int64, m×n),
// all row-major, decide whether A·B == Y over ℤ with O(reps·(mk + kn + mn))
// field operations instead of the O(mkn) recomputation — Freivalds' random
// projection: embed every entry into F by the sign-correct map
// x ↦ x mod p for x ≥ 0, x ↦ p − (|x| mod p) for x < 0 (gkr_field::FromSigned),
// draw a uniform vector r ∈ F^n and test  A·(B·r) == Y·r  in F. The left side
// is evaluated as two matrix-vector products (NEVER forming A·B), which is
// the whole point of the complexity claim.
//
//   • Completeness: if A·B = Y over ℤ then A·(B·r) = (A·B)·r = Y·r for EVERY
//     r ∈ F^n — associativity of F-linear maps; the check passes always.
//   • Soundness: if A·B ≠ Y, let D = A·B − Y ≠ 0 in F^{m×n} (nonzero by the
//     embedding-exactness argument below). Each nonzero row of D defines a
//     nonzero degree-1 form ℓ(r) = Σ_j D_ij·r_j; fixing all coordinates of r
//     except one with a nonzero coefficient, exactly ONE value of that
//     coordinate zeroes ℓ. Hence Pr_r[ℓ(r) = 0] ≤ max_c Pr[r_j = c], which is
//     1/p for uniform r (the degree-1 DeMillo–Lipton–Schwartz–Zippel bound).
//
// EMBEDDING EXACTNESS (why the mod-p check decides the INTEGER statement):
// every entry of the true product A·B is an exact int64 sum of k products of
// two int8 values, so |(A·B)_ij| ≤ k·128·128 = k·2^14; the honest Y satisfies
// the same bound and any int64 Y satisfies |Y_ij| ≤ 2^63. FromSigned is a
// homomorphism ℤ → F, and it maps an integer d to 0 iff p | d; here
// |D_ij| = |(A·B)_ij − Y_ij| ≤ k·2^14 + 2^63 < 2^64 − 2^32 + 1 = p for every
// k ≤ 2^40, so D_ij embeds to 0 in F iff D_ij = 0 in ℤ. The F-statement
// A·B = Y is therefore EQUIVALENT to the ℤ-statement for all supported
// shapes: no wraparound ambiguity, the verdict is exact. (The test suite
// exercises the ±127 high-magnitude regime to pin this.)
//
// CHALLENGE DERIVATION (frozen; deterministic and re-derivable by anyone
// holding the 32-byte seed): the SHA256d counter-XOF of the FRI/AlgHash
// stack (Sha256dBytes, matmul_v4_rc_fri_ext3.h) with a dedicated domain tag,
//
//   r_j = FromChallengeBytes( SHA256d( seed[32 bytes, uint256 memory order]
//                                      ‖ "BTX_RC_FRV_V1" ‖ LE32(rep)
//                                      ‖ LE32(j) ) )
//
// where FromChallengeBytes takes the LOW 8 little-endian bytes of the 32-byte
// digest as a uint64 and reduces mod p (matmul_v4_rc_gkr_field.h). r_j
// depends only on (seed, rep, j) — a pure function; in particular the length-n
// vector for a given rep is prefix-consistent across n.
//
// SOUNDNESS STATEMENT (per rep and total). Modeling the SHA256d digests as
// uniform 64-bit words, the mod-p reduction gives each field element
// probability 1/2^64 or 2/2^64 (the 2^32 − 1 residues below 2^64 − p are hit
// twice; total bias < 2^-32). Plugging max_c Pr[r_j = c] ≤ 2/2^64 into the
// degree-1 bound above: a FALSE claim survives one rep with probability
// ≤ 2^-63, and survives all `reps` independent domain-separated reps with
// probability ≤ 2^(−63·reps). reps = 1 already meets the ~2^-64-scale
// consensus target; reps is exposed for margin only.

namespace matmul::v4::rc {

/** Frozen domain tag of the Freivalds challenge XOF (see derivation above). */
inline constexpr char kRCFreivaldsDomainTag[] = "BTX_RC_FRV_V1";

/**
 * The per-rep field-vector challenge derivation, exposed for tests/reuse:
 * r_j = FromChallengeBytes(SHA256d(seed ‖ "BTX_RC_FRV_V1" ‖ LE32(rep) ‖
 * LE32(j))), j ∈ [0, n). Pure function of (challenge_seed, rep, n).
 */
[[nodiscard]] std::vector<gkr_field::Fp> FreivaldsChallengeVector(
    const uint256& challenge_seed, uint32_t rep, uint32_t n);

/**
 * Verify A·B == Y (A:int8 m×k, B:int8 k×n, Y:int64 m×n, all row-major) by
 * `reps` independent Freivalds projections drawn from `challenge_seed`.
 * Returns true iff every projection matched. O(reps·(mk+kn+mn)).
 *
 * Fail-closed: returns false (with a `why` message when non-null) on any
 * shape mismatch (A.size() != m·k etc.) or reps == 0. A false claim passes
 * with probability ≤ 2^(−63·reps) over the seed (see header comment).
 */
[[nodiscard]] bool FreivaldsCheckGemm(
    const std::vector<int8_t>& A, const std::vector<int8_t>& B,
    const std::vector<int64_t>& Y, uint32_t m, uint32_t k, uint32_t n,
    const uint256& challenge_seed, uint32_t reps, std::string* why = nullptr);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_FREIVALDS_H
