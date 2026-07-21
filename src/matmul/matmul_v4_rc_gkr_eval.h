// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_GKR_EVAL_H
#define BTX_MATMUL_MATMUL_V4_RC_GKR_EVAL_H

#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// EVALUATION ARGUMENT (blueprint §2.4) — v7 FOUNDATION interface.
//
// Every relation of the v7 verifier reduces to claims "ṽ(r) = c" for committed
// columns v and FS-derived multilinear points r. By §1.3, with the column
// committed in the COEFFICIENT basis (coefficient i = wire value v_i, exactly
// what FriBatchCommit commits), each claim is the inner product
//
//   ⟨coeffs(P_v), coeffs(q_r)⟩ = c,   q_r(X) := Π_b ((1−r_b) + r_b·X^(2^b)),
//
// where coefficient i of q_r is eq(r, bits(i)) (little-endian bit order,
// matching EqFactor / RCGkrMleEval1D2). The verifier evaluates q_r at any
// point in O(ν) multiplications — RCGkrEqKernelAt below.
//
// AGGREGATION (Wave-2 contract, Aurora univariate sumcheck / Lemma 1.2):
//  1. Collect M claims; FS weights μ_1..μ_M drawn AFTER all claims and all
//     epoch-1 column roots are absorbed.
//  2. Prover forms h(X) = X · Σ_m μ_m·P_{v_m}(X)·q*_{r_m}(X), with
//     q*_r(X) = X^{κ−1}·q_r(1/X) the coefficient-reversed kernel, and commits
//     the Lemma 1.2 witnesses f (deg < N−1), g (deg < N) as TWO MORE COLUMNS
//     inside the SAME batched FRI instance (second commitment epoch: the
//     batch's λ, z1, z2 are drawn after the f/g roots — FriBatchCommit already
//     enforces this because ALL column roots are absorbed before λ).
//  3. Verifier checks the Lemma 1.2 identity
//       h(z) = g(z)·(z^N − 1) + z·f(z) + σ/N,  σ = Σ_m μ_m·c_m,
//     at BOTH OOD points z1, z2 (dual-OOD — single point caps degree at 2^24
//     < κ = 2^28) using:
//       • the bound per-column openings C_i(z1), C_i(z2) that FriBatchVerify
//         certifies (proof.evals_z1 / proof.evals_z2 — THE opening primitive
//         this interface consumes), and
//       • its own O(ν) evaluations of q*_{r_m}(z) = z^{κ−1}·q_{r_m}(z^{-1});
//     and re-checks the identity at every FRI query site from the per-column
//     query openings.
//  Soundness (Theorem 2.2): ε_eval ≤ 2^40·[(M−1)/|Fp2| + (2κ/(|Fp2|−2^32))²]
//  ≤ 2^-76 for M ≤ 2^12, conditioned on Theorem 2.1 (FriBatchVerify).
//
// Downstream use (relations §3–§4): after ProveProductK yields (r_i, r_k) and
// (r_k, r_j), the A/B/trace openings are queued as RCGkrOpeningClaim's against
// the layout-designated columns (transposed operands swap the point halves —
// M̃ᵀ(r,s) = M̃(s,r) — and multi-chunk tensors fold chunk openings with the
// top-variable eq-weights; both are caller-side point manipulations, not new
// commitments).
//
// This header is the frozen Wave-2 build-against interface. The batched-FRI
// opening primitive (dual-OOD bound per-column evaluations + per-query column
// openings) is IMPLEMENTED and tested in matmul_v4_rc_fri.{h,cpp};
// EvalArgumentProve/Verify bodies land in matmul_v4_rc_gkr_eval.cpp (Wave-2).
// ============================================================================

namespace matmul::v4::rc {

using gkr_field::Fp2;

inline constexpr uint32_t kRCGkrEvalArgVersion = 1;
/** M ≤ 2^12 keeps the (M−1)/|Fp2| aggregation term ≥ 76 bits post-grinding
 *  (soundness table row "RLC batching λ/μ/γ/weights"). */
inline constexpr uint32_t kRCGkrEvalArgMaxClaims = 1u << 12;

/** One MLE opening claim against a committed column (blueprint §10). */
struct RCGkrOpeningClaim {
    /** Index into the batched column list (FriBatchProof::columns order). */
    uint32_t column_id{0};
    /** Multilinear point, little-endian bit order (EqFactor convention);
     *  point.size() = ν = log2 of the column's padded length. */
    std::vector<Fp2> point;
    /** Claimed ṽ(point). NOT prover-free in v7: derived per relation (e.g.
     *  final_eval := a_eval·b_eval is checked, never carried). */
    Fp2 value{};
};

/**
 * Coefficients of the eq-kernel q_r: coefficient i = eq(r, bits(i)) for
 * i < 2^ν (prover-side; O(2^ν)). Satisfies, for any column v of length ≤ 2^ν:
 *   Σ_i v_i·q_coeffs[i] = RCGkrMleEval1D2(v, r)   (the §1.3 correspondence).
 */
[[nodiscard]] inline std::vector<Fp2> RCGkrEqKernelCoeffs(const std::vector<Fp2>& r)
{
    std::vector<Fp2> c;
    c.reserve(size_t{1} << r.size());
    c.push_back(Fp2::One());
    for (size_t b = 0; b < r.size(); ++b) {
        const size_t half = c.size();
        c.resize(half * 2);
        for (size_t i = 0; i < half; ++i) {
            c[half + i] = gkr_field::Mul(c[i], r[b]);
            c[i] = gkr_field::Mul(c[i], gkr_field::Sub(Fp2::One(), r[b]));
        }
    }
    return c;
}

/** Verifier-side O(ν) evaluation q_r(x) = Π_b ((1−r_b) + r_b·x^(2^b)). */
[[nodiscard]] inline Fp2 RCGkrEqKernelAt(const std::vector<Fp2>& r, const Fp2& x)
{
    Fp2 acc = Fp2::One();
    Fp2 xp = x;
    for (size_t b = 0; b < r.size(); ++b) {
        acc = gkr_field::Mul(
            acc, gkr_field::Add(gkr_field::Sub(Fp2::One(), r[b]), gkr_field::Mul(r[b], xp)));
        xp = gkr_field::Mul(xp, xp);
    }
    return acc;
}

/** Aggregated evaluation-argument proof (Wave-2). The f/g Lemma-1.2 witnesses
 *  are NOT separate commitments: they are columns f_column/g_column inside the
 *  same FriBatchProof, so their openings ride the batch's dual-OOD/query
 *  machinery for free. */
struct RCGkrEvalArgumentProof {
    uint32_t version{kRCGkrEvalArgVersion};
    /** Aggregated inner product σ = Σ_m μ_m·c_m. Verifier recomputes from the
     *  claims and FS μ's and REJECTS on mismatch (never trusted). */
    Fp2 sigma{};
    /** Column ids (into the batch) of the Lemma 1.2 witnesses. */
    uint32_t f_column{0};
    uint32_t g_column{0};
};

struct RCGkrEvalArgumentProveResult {
    RCGkrEvalArgumentProof proof;
    /** Coefficients of f (deg < N−1) and g (deg < N) — the caller appends them
     *  to the column list of the (single) FriBatchCommit invocation. */
    std::vector<Fp2> f_coeffs;
    std::vector<Fp2> g_coeffs;
    bool ok{false};
    std::string note;
};

/**
 * WAVE-2 (declaration only; implement in matmul_v4_rc_gkr_eval.cpp).
 * Prover side of §2.4: derive μ_1..μ_M from fs_seed (which MUST already bind
 * all epoch-1 column roots and every claim), build h, divide by Z_D per
 * Lemma 1.2 into (f, g), and return them for second-epoch commitment.
 * `columns` are the epoch-1 committed columns (coefficient basis), indexed by
 * RCGkrOpeningClaim::column_id.
 */
[[nodiscard]] RCGkrEvalArgumentProveResult EvalArgumentProve(
    const std::vector<RCGkrOpeningClaim>& claims,
    const std::vector<std::vector<Fp2>>& columns, const uint256& fs_seed);

/**
 * WAVE-2 (declaration only; implement in matmul_v4_rc_gkr_eval.cpp).
 * Verifier side of §2.4: recompute μ's and σ from fs_seed + claims; check the
 * Lemma 1.2 identity at batch.z1 AND batch.z2 using batch.evals_z1/evals_z2
 * (bound by a PRIOR successful FriBatchVerify — call it first) and O(ν)
 * kernel evaluations; re-check the identity at every batch query site from
 * FriBatchQuery::columns. Rejects iff any aggregated claim is false, except
 * with ε_eval ≤ 2^-76 (Theorem 2.2).
 */
[[nodiscard]] bool EvalArgumentVerify(const std::vector<RCGkrOpeningClaim>& claims,
                                      const FriBatchProof& batch,
                                      const RCGkrEvalArgumentProof& proof,
                                      const uint256& fs_seed, std::string* why = nullptr);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_GKR_EVAL_H
