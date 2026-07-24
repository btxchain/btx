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
// CHALLENGE DERIVATION (deterministic and re-derivable by anyone
// holding the 32-byte seed): the SHA256d counter-XOF of the FRI/AlgHash
// stack (Sha256dBytes, matmul_v4_rc_fri_ext3.h) with a dedicated domain tag,
//
//   retry=0: r_j = low64(SHA256d(seed ‖ "BTX_RC_FRV_V1" ‖ LE32(rep) ‖ LE32(j)))
//   retry>0: r_j = low64(SHA256d(seed ‖ "BTX_RC_FRV_V1" ‖ LE32(rep) ‖ LE32(j)
//                                ‖ LE32(retry)))
//
// The first candidate < p is accepted. Candidates in [p,2^64) are rejected, not
// reduced, so r_j is exactly uniform over Goldilocks Fp. r_j depends only on
// (seed, rep, j) — a pure function; in particular the length-n vector for a
// given rep is prefix-consistent across n.
//
// SOUNDNESS STATEMENT (per rep and total). Modeling SHA256d as a random oracle,
// rejection sampling makes every r_j uniform over Fp, so a FALSE claim survives
// one rep with probability ≤ 1/p and survives all `reps` independent domain-
// separated reps with probability ≤ p^(-reps). reps = 1 already meets the
// ~2^-64-scale consensus target; reps is exposed for margin only.

namespace matmul::v4::rc {

/** Frozen domain tag of the Freivalds challenge XOF (see derivation above). */
inline constexpr char kRCFreivaldsDomainTag[] = "BTX_RC_FRV_V1";

/**
 * The per-rep field-vector challenge derivation, exposed for tests/reuse:
 * r_j is rejection-sampled from SHA256d(seed ‖ "BTX_RC_FRV_V1" ‖ LE32(rep) ‖
 * LE32(j) [‖ LE32(retry)]), j in [0, n). Pure function of
 * (challenge_seed, rep, n).
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
 * with probability ≤ p^(-reps) over the seed (see header comment).
 */
[[nodiscard]] bool FreivaldsCheckGemm(
    const std::vector<int8_t>& A, const std::vector<int8_t>& B,
    const std::vector<int64_t>& Y, uint32_t m, uint32_t k, uint32_t n,
    const uint256& challenge_seed, uint32_t reps, std::string* why = nullptr);

// ============================================================================
// SEGMENT-FREIVALDS — verify a GEMM whose contraction is presented as a set of
// CONTRACTION SEGMENTS, keeping per-check relay/compute BOUNDED by the segment
// footprint rather than the full operand size. This is the primitive the
// datacenter sampled carrier uses so a sampled layer's relayed bytes do not
// scale with the (production-sized) contraction k or output m·n.
//
// THE MATH (how segment sampling + the random projection compose). Split the
// contraction [0,k) into P disjoint segments; segment p contributes the partial
// product  Y_p = A[:,seg_p] · B[seg_p,:]  and, EXACTLY over ℤ,
//        Y  =  Σ_{p∈[P]} Y_p                                             (I)
// because integer matmul is linear in the contraction index. Freivalds' random
// projection is F-LINEAR, so for a uniform r ∈ F^n
//        Y·r  =  Σ_p (A[:,seg_p]·(B[seg_p,:]·r))                         (II)
// and the identity (I) is checked by ONE projection over the WHOLE segment set:
// evaluate each segment's mat-vec A_p·(B_p·r) (never forming A_p·B_p), sum them,
// and compare to Y·r. Completeness is EXACT — (II) holds for every r when (I)
// holds. Soundness: if Σ_p A_p·B_p ≠ Y then D = (Σ_p A_p·B_p) − Y ≠ 0 in
// F^{m×n} (same embedding-exactness argument as FreivaldsCheckGemm; each entry
// |D_ij| ≤ (Σ_p k_p)·2^14 + 2^63 < p), so a false claim survives one rep with
// probability ≤ 1/p and all `reps` reps with probability ≤ p^(-reps).
//
// COMPOSITION WITH SEGMENT SAMPLING (the carrier's deterrence envelope). The
// per-check relay footprint of ONE segment p is |seg_p|·(m_rows + n_cols) int8
// (its operand slices) plus the m_rows·n_cols int64 output — independent of the
// UNSAMPLED contraction. Passing only a SUBSET Ω ⊂ [P] of segments to this
// function verifies Σ_{p∈Ω} A_p·B_p == Y_Ω exactly (each rep ≤ 1/p), where
// Y_Ω is the caller-supplied partial-sum target; the UNSAMPLED contraction
// [0,k)∖Ω is not covered and folds into the sampling residual ρ* (the
// deterrence envelope of matmul_v4_rc_freivalds_sampled.h). A layer whose GEMM
// error is BROAD (a skipped / approximated / low-precision GEMM — its error
// spans the contraction) is caught with probability ≥ (1−p^(-reps)) by ANY
// covered segment; only an error CONCENTRATED entirely in the unsampled
// contraction escapes — that concentrated-escape is the ρ* residual, priced
// exactly as the whole-layer sampling residual, NOT a new soundness claim.
//
// Per-segment / per-layer detection probability (closed form). For a sampled
// layer with P contraction segments, sampling |Ω| of them, a contraction-
// localized error confined to one segment is detected with probability
// |Ω|/P · (1 − p^(-reps)); a broad error is detected w.p. ≥ 1 − p^(-reps).

/** One contraction segment's operand slices for the sum A·B over its k_p rows:
 *  A_slice is (m × k_p) int8 (the sampled OUTPUT rows × this segment's
 *  contraction indices), B_slice is (k_p × n) int8. */
struct FreivaldsSegmentOperand {
    std::vector<int8_t> A_slice; // m × k_p, row-major
    std::vector<int8_t> B_slice; // k_p × n, row-major
    uint32_t k_p{0};             // this segment's contraction length
};

/**
 * Verify Σ_p (segments[p].A_slice · segments[p].B_slice) == Y (int64 m×n,
 * row-major) by `reps` independent Freivalds projections drawn from
 * `challenge_seed`. Every A_slice is m×k_p, every B_slice is k_p×n; the k_p may
 * differ per segment. Returns true iff every projection matched.
 * O(reps·Σ_p (m·k_p + k_p·n + m·n)) — never Σ_p m·k_p·n.
 *
 * Fail-closed: returns false (with `why` when non-null) on reps==0, empty
 * segment set, or any per-segment shape mismatch (A_slice.size()!=m·k_p etc.).
 * Completeness EXACT; a false claim passes with probability ≤ p^(-reps).
 */
[[nodiscard]] bool FreivaldsCheckGemmSegments(
    const std::vector<FreivaldsSegmentOperand>& segments,
    const std::vector<int64_t>& Y, uint32_t m, uint32_t n,
    const uint256& challenge_seed, uint32_t reps, std::string* why = nullptr);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_FREIVALDS_H
