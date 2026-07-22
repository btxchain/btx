// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_GKR_EVAL_H
#define BTX_MATMUL_MATMUL_V4_RC_GKR_EVAL_H

#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_fri_ext3.h>
#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
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
// Fp3 is pulled in for the v7 episode-path siblings below. GF(p^2) is NOT a
// subfield of GF(p^3) (2 ∤ 3), so the Fp2 and Fp3 pipelines never mix values;
// the base field Fp embeds into both.
using gkr_field::Fp3;

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

/** Fp3 sibling of RCGkrOpeningClaim (v7 episode path; Fri3Batch* backend). */
struct RCGkrOpeningClaim3 {
    uint32_t column_id{0};
    std::vector<Fp3> point;
    Fp3 value{};
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

/** Fp3 sibling of RCGkrEqKernelCoeffs (v7 episode path). */
[[nodiscard]] inline std::vector<Fp3> RCGkrEqKernelCoeffs3(const std::vector<Fp3>& r)
{
    std::vector<Fp3> c;
    c.reserve(size_t{1} << r.size());
    c.push_back(Fp3::One());
    for (size_t b = 0; b < r.size(); ++b) {
        const size_t half = c.size();
        c.resize(half * 2);
        for (size_t i = 0; i < half; ++i) {
            c[half + i] = gkr_field::Mul(c[i], r[b]);
            c[i] = gkr_field::Mul(c[i], gkr_field::Sub(Fp3::One(), r[b]));
        }
    }
    return c;
}

/** Fp3 sibling of RCGkrEqKernelAt (v7 episode path). */
[[nodiscard]] inline Fp3 RCGkrEqKernelAt3(const std::vector<Fp3>& r, const Fp3& x)
{
    Fp3 acc = Fp3::One();
    Fp3 xp = x;
    for (size_t b = 0; b < r.size(); ++b) {
        acc = gkr_field::Mul(
            acc, gkr_field::Add(gkr_field::Sub(Fp3::One(), r[b]), gkr_field::Mul(r[b], xp)));
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

// ----------------------------------------------------------------------------
// Fp3 siblings of the §2.4 aggregated evaluation argument (v7 EPISODE path).
// Same Aurora/Lemma-1.2 construction over K = F_{p^3} (|K| ≈ 2^192), riding
// the Fri3Batch* backend. Soundness: ε_eval ≤ 2^40·[(M−1)/|Fp3| +
// (2κ/(|Fp3|−2^32))²] — the FS terms sit ≈ 63 bits BELOW the 2^-76.8 query
// floor, so the composed opening bound is query-dominated (the Fp2 pipeline
// for the legacy v6/coupled paths is unchanged above).
// ----------------------------------------------------------------------------

struct RCGkrEvalArgumentProof3 {
    uint32_t version{kRCGkrEvalArgVersion};
    /** σ = Σ_m μ_m·c_m over Fp3 — recomputed and checked, never trusted. */
    Fp3 sigma{};
    uint32_t f_column{0};
    uint32_t g_column{0};
};

struct RCGkrEvalArgumentProveResult3 {
    RCGkrEvalArgumentProof3 proof;
    std::vector<Fp3> f_coeffs;
    std::vector<Fp3> g_coeffs;
    bool ok{false};
    std::string note;
};

/** Fp3 sibling of EvalArgumentProve (columns/claims over Fp3; the caller
 *  appends f/g to the single Fri3BatchCommit column list). */
[[nodiscard]] RCGkrEvalArgumentProveResult3 EvalArgumentProve3(
    const std::vector<RCGkrOpeningClaim3>& claims,
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed);

/** Fp3 sibling of EvalArgumentVerify against a Fri3BatchVerify-authenticated
 *  batch (call Fri3BatchVerify FIRST). */
[[nodiscard]] bool EvalArgumentVerify3(const std::vector<RCGkrOpeningClaim3>& claims,
                                       const Fri3BatchProof& batch,
                                       const RCGkrEvalArgumentProof3& proof,
                                       const uint256& fs_seed, std::string* why = nullptr);

// ============================================================================
// CONSTRUCTION I — the batched multilinear evaluation opening.
//
// STATEMENT (finite-field algebra over F_p, p = 2^64−2^32+1, and K = F_{p^2}).
// For vectors u ∈ F^{2^ℓ} bound by the Merkle root of their low-degree-
// extension table (coefficient-basis columns of ONE FriBatch instance),
// points z ∈ K^ℓ and claimed scalars y, establish the polynomial identity
// ũ(z) = y, where ũ(X) = Σ_x u_x·eq(X,x) is the multilinear extension, at
// checking cost O(ℓ) per claim + ONE low-degree-proximity opening. For any
// y ≠ ũ(z) the identity check evaluates to a NONZERO field element except
// with the separation probability quantified below
// (RCGkrConstructionISeparationBits()).
//
// TECHNIQUE (two stages, composed):
//  STAGE 1 — γ-batched eq-sumcheck (EvalOpenProve/Verify). With FS γ, run ONE
//    ν-round degree-2 sumcheck on
//      F(x) := Σ_m γ^m · u_{c(m)}(x) · eq(z_m, x),   Σ_x F(x) = Σ_m γ^m·y_m,
//    eq(z,x) = Π_b (z_b x_b + (1−z_b)(1−x_b)). Per bound variable F is a
//    product of two multilinears ⇒ round messages are degree ≤ 2 (S1, d=2).
//    The sumcheck ends at a COMMON random point r ∈ K^ν with one residual
//    claim ũ_c(r) per DISTINCT column c — the checking routine tests the
//    chain end against the transcript's ũ_c(r) using its own O(M·ν) native
//    eq(z_m, r) evaluations.
//  STAGE 2 — binding ũ_c(r) to the ROOT-BOUND column (EvalArgument*, §2.4).
//    The reduced claims at r are aggregated with FS μ into the Aurora
//    univariate identity whose f/g assignment-columns ride the SAME batched
//    FRI; the dual-OOD DEEP openings bind every C_c(z1), C_c(z2) to the
//    unique low-degree codeword (Theorems 2.1/2.2). This is the low-degree-
//    quotient binding of the claimed scalar to the LDE behind the root: a
//    residual claim ũ_c(r) ≠ the true value makes the Lemma-1.2 identity a
//    nonzero polynomial of degree < 2n, detected at both z1, z2.
//
// WHY THE γ-BATCH IS A SINGLE PROXIMITY INSTANCE (critical): all columns
// (A, B, Y, X, …) live in ONE FriBatchCommit; the random linear combination
// λ (inside the batch) + γ (across claims) + μ (across reduced openings)
// compose so the whole statement rides ONE FRI query phase — no union-bound
// loss across per-column FRI instances (§2.3: seven instances ⇒ ≥ 7·2^-65.85
// ≈ 2^-63.05, FAILING 2^-64; one batched instance restores 2^-76.8).
//
// SEPARATION BOUND (obligation (b), composed, |K| = p² > 2^127.99, protocol
// caps ν ≤ 28 = log2 κ, M ≤ 2^12 claims, W ≤ 2^12 columns, grinding g = 40):
//   pre-grinding FS terms —
//     γ-batching (powers of one γ):        (M−1)/|K|        ≤ 2^-116
//     eq-sumcheck, ν rounds, deg ≤ 2 (S1): 2ν/|K|           ≤ 2^-122.2
//     μ-aggregation of reduced openings:   (M−1)/|K|        ≤ 2^-116
//     batch RLC λ + DEEP weights w1,w2:    (W+2)/|K|        ≤ 2^-116
//     dual-OOD bad-point pairs (S5):       (2κ/(|K|−2^32))² ≤ 2^-196
//   FS subtotal ≤ 3·2^-116 + 2^-122.2 ≈ 2^-114.4; ×2^40 (S6) ⇒ ≤ 2^-74.4.
//   Batched-FRI query term (S4, post-grind): 2^-76.8
//     (Q=128 ⇒ FriBatchSoundnessBoundBits()=76).
//   SHA256d Merkle/transcript bindings (2^40-query adversary): ≤ 2^-88.
//   ε_total ≤ 2^-74.4 + 2^-76.8 + 2^-88 < 2^-74  ⇒  −log2(ε_total) ≥ 74,
//   clearing the 2^-64 target with ≥ 10 bits of margin.
//
// COMPLETENESS (obligation (a)): for a valid assignment (u, z, y = ũ(z))
// every check is an exact algebraic identity — round sums, the final eq
// identity, the Lemma-1.2 coefficient identities, and the FRI/DEEP openings —
// so the checking routine accepts with probability 1
// (tests: matmul_v4_rc_gkr_eval_tests).
//
// COUNTEREXAMPLES (obligation (c), same test file): the identity evaluates
// NONZERO on every tested invalid assignment. An internally-consistent
// transcript for y' ≠ ũ(z) (round sums repaired by constant shifts, chain end
// repaired via a fabricated ũ_c(r)) satisfies ALL Stage-1 algebra and is
// detected exactly at Stage 2 (eval:identity_z1/z2); a wrong γ-combination
// (claims permuted, or a foreign FS seed) is detected at Stage 1; the valid
// assignment passes.
// ============================================================================

inline constexpr uint32_t kRCGkrEvalOpenVersion = 1;
inline constexpr uint32_t kRCGkrConstructionIVersion = 1;

/** Composed separation bound of Construction I: −log2(ε_total) ≥ 76 after the
 *  2^40 grinding budget. Fp3 EPISODE REGIME (2026-07-22 cutover): the FS
 *  subtotal terms move to |K| = p³ ≈ 2^192 (γ/μ/λ/w ≤ 3·2^-180, eq-sumcheck
 *  ≤ 2^-186, dual-OOD ≤ 2^-326; ×2^40 ⇒ ≤ 2^-138.4), so the binding floor is
 *  the field-independent batched-FRI query term 2^-76.8
 *  (= FriBatchSoundnessBoundBits()/Fri3BatchSoundnessBoundBits() = 76):
 *  ε_total ≤ 2^-138.4 + 2^-76.8 + 2^-88 < 2^-76. (Historical Fp2 value: 74,
 *  dominated by the Fp2 FS subtotal 2^-74.4.) */
[[nodiscard]] inline constexpr int RCGkrConstructionISeparationBits() { return 76; }
static_assert(RCGkrConstructionISeparationBits() >= kRCFriTargetSoundnessBits + 10,
              "Construction I must clear the 2^-64 target with >= 10 bits margin");

/** Native O(ν) eq(a, b) = Π_b (a_b·b_b + (1−a_b)(1−b_b)). Requires equal dims. */
[[nodiscard]] inline Fp2 RCGkrEqAt(const std::vector<Fp2>& a, const std::vector<Fp2>& b)
{
    Fp2 acc = Fp2::One();
    for (size_t i = 0; i < a.size() && i < b.size(); ++i) {
        const Fp2 one_minus_a = gkr_field::Sub(Fp2::One(), a[i]);
        const Fp2 one_minus_b = gkr_field::Sub(Fp2::One(), b[i]);
        acc = gkr_field::Mul(acc, gkr_field::Add(gkr_field::Mul(a[i], b[i]),
                                                 gkr_field::Mul(one_minus_a, one_minus_b)));
    }
    return acc;
}

/** One eq-sumcheck round message: g(0), g(1), g(2) (degree-2 product round).
 *  Deliberately distinct from RCGkrSumcheckRound (matmul_v4_rc_gkr.h) — this
 *  header must not include the full gkr header (inclusion is the other way). */
struct RCGkrEvalSumcheckRound {
    Fp2 g0{};
    Fp2 g1{};
    Fp2 g2{};
};

/** Stage-1 transcript of Construction I: the γ-batched eq-sumcheck. */
struct RCGkrEvalOpenProof {
    uint32_t version{kRCGkrEvalOpenVersion};
    /** ν rounds (ν = log2 of the batch's padded column length). */
    std::vector<RCGkrEvalSumcheckRound> rounds;
    /** Residual ũ_c(r) per DISTINCT referenced column, in first-use order over
     *  the claims. Bound to the column roots by Stage 2 — NEVER trusted alone. */
    std::vector<Fp2> column_at_r;
};

struct RCGkrEvalOpenProveResult {
    RCGkrEvalOpenProof proof;
    /** The common reduced point r ∈ K^ν (little-endian, EqFactor convention). */
    std::vector<Fp2> r;
    /** One reduced opening claim {column_id, r, ũ_c(r)} per distinct column —
     *  feed these (plus any other §2.4 claims) into EvalArgumentProve. */
    std::vector<RCGkrOpeningClaim> reduced;
    /** SHA256d digest of the full Stage-1 transcript (γ, rounds, residuals):
     *  the fs_seed for the Stage-2 μ-aggregation (two-epoch discipline). */
    uint256 bind_digest{};
    bool ok{false};
    std::string note;
};

/**
 * Stage 1 constructing routine. `claims` are (column_id, z, y) triples;
 * points of dimension < ν are zero-extended internally (selects the low
 * sub-cube of the padded column — valid because 2^{|z|} must cover the
 * column's logical length, enforced). fs_seed MUST already bind the epoch-1
 * column roots and the statement (commit-then-challenge). The routine refuses
 * an invalid assignment (ok=false, "claims disagree with columns") — the
 * internally-consistent invalid transcripts for the regression tests go
 * through BatchedOpeningProveInvalidAssignmentForTest.
 */
[[nodiscard]] RCGkrEvalOpenProveResult EvalOpenProve(
    const std::vector<RCGkrOpeningClaim>& claims,
    const std::vector<std::vector<Fp2>>& columns, uint32_t nu, const uint256& fs_seed);

/**
 * Stage 1 checking routine: recompute γ, replay the round-sum chain, check
 * the chain end against Σ_c ũ_c(r)·Σ_{m on c} γ^m·eq(z_m, r) with native
 * O(M·ν) eq evaluations. On success outputs the reduced claims at r
 * (out_reduced) and the Stage-2 seed (out_bind_digest). The reduced claims
 * are NOT yet bound to the column roots — the caller MUST pass them through
 * EvalArgumentVerify against a FriBatchVerify-authenticated batch
 * (BatchedOpeningVerify does the full composition).
 */
[[nodiscard]] bool EvalOpenVerify(const std::vector<RCGkrOpeningClaim>& claims, uint32_t nu,
                                  const RCGkrEvalOpenProof& proof, const uint256& fs_seed,
                                  std::vector<RCGkrOpeningClaim>* out_reduced,
                                  uint256* out_bind_digest, std::string* why = nullptr);

/** Construction I end-to-end transcript: Stage-1 eq-sumcheck + Stage-2
 *  aggregated opening + the ONE batched FRI instance every column (and f/g)
 *  rides. */
struct RCGkrBatchedOpeningProof {
    uint32_t version{kRCGkrConstructionIVersion};
    RCGkrEvalOpenProof sumcheck;
    RCGkrEvalArgumentProof eval;
    FriBatchProof batch;
};

struct RCGkrBatchedOpeningProveResult {
    RCGkrBatchedOpeningProof proof;
    bool ok{false};
    std::string note;
};

/**
 * Construction I constructing routine: bind all columns by their LDE Merkle
 * roots (epoch-1 roots → γ seed), run the γ-batched eq-sumcheck, aggregate
 * the reduced openings (μ), commit f/g inside the SAME FriBatchCommit, all
 * under fs_seed (which must bind the outer statement).
 */
[[nodiscard]] RCGkrBatchedOpeningProveResult BatchedOpeningProve(
    const std::vector<RCGkrOpeningClaim>& claims,
    const std::vector<std::vector<Fp2>>& columns, const uint256& fs_seed);

/**
 * Construction I checking routine. Order of checks: shape → FriBatchVerify
 * (binds column roots + dual-OOD evals) → Stage-1 sumcheck replay → Stage-2
 * EvalArgumentVerify of the reduced claims. Any claim set containing an
 * invalid ũ(z) ≠ y is detected except with separation probability
 * ε_total ≤ 2^-74 (obligation (b)).
 */
[[nodiscard]] bool BatchedOpeningVerify(const std::vector<RCGkrOpeningClaim>& claims,
                                        const RCGkrBatchedOpeningProof& proof,
                                        const uint256& fs_seed, std::string* why = nullptr);

/**
 * TEST-ONLY (invalid-assignment regression, mirroring the
 * ProveMaliciousEpisodeV7ForTest precedent): the STRONGEST internally-
 * consistent transcript for a claim set that may contain y' ≠ ũ(z). Repairs
 * every round sum (constant shift into g(0)) and the chain end (a fabricated
 * ũ_c(r) solving the final identity), so the transcript satisfies ALL
 * Stage-1 algebra and survives until the Stage-2 root binding, where the
 * Lemma-1.2 identity evaluates NONZERO at z1/z2 and the checking routine
 * MUST reject (eval:identity_z1/z2). Never called outside tests.
 */
[[nodiscard]] RCGkrBatchedOpeningProveResult BatchedOpeningProveInvalidAssignmentForTest(
    const std::vector<RCGkrOpeningClaim>& claims,
    const std::vector<std::vector<Fp2>>& columns, const uint256& fs_seed);

// ============================================================================
// G1/G2/G5 BINDING PIECES (blueprint §3.1/§4.2) — pure claim/point builders
// consumed by the integration layer. This header provides the primitive ONLY;
// VerifyWinnerProofV7 / matmul_v4_rc_gkr.cpp wiring is the integration
// agent's job and is NOT touched here.
// ============================================================================

/**
 * Row-major matrix MLE point (§1.2): for M padded to 2^{ν_i}×2^{ν_j} with
 * flat index i·2^{ν_j}+j, the little-endian coordinates are LOW ν_j = column
 * bits (r_col), HIGH ν_i = row bits (r_row); zero-extension to nu selects the
 * low sub-cube of the zero-padded committed column (PointConcatExtend
 * convention). Valid when the committed row stride is the power-of-two 2^{ν_j}
 * (all v7 toy tensors; multi-chunk/ragged tensors go through
 * RCGkrSegmentPoint / RCGkrFoldChunkClaims instead).
 */
[[nodiscard]] inline std::vector<Fp2> RCGkrMatMlePoint(const std::vector<Fp2>& r_row,
                                                       const std::vector<Fp2>& r_col, uint32_t nu)
{
    std::vector<Fp2> p;
    p.reserve(nu);
    p.insert(p.end(), r_col.begin(), r_col.end());
    p.insert(p.end(), r_row.begin(), r_row.end());
    while (p.size() < nu) p.push_back(Fp2::Zero());
    return p;
}

/**
 * G1 — operand-scalar binding (§3.1 step 4): the opening claim for
 * Ã(r_row, r_col) (or, with transposed=true, the TRANSPOSED VIEW of the same
 * commitment: M̃ᵀ(r_row, r_col) = M̃(r_col, r_row) — §1.2, "transpose is
 * free", no extra committed data). Use for a_at_r = Ã(r_i, r_k) via
 * (a_col, r_i, r_k) and b_at_r = B̃(r_k, r_j) via (b_col, r_k, r_j).
 */
[[nodiscard]] inline RCGkrOpeningClaim RCGkrMatrixOpeningClaim(
    uint32_t column_id, const std::vector<Fp2>& r_row, const std::vector<Fp2>& r_col, uint32_t nu,
    const Fp2& value, bool transposed = false)
{
    return RCGkrOpeningClaim{column_id,
                             transposed ? RCGkrMatMlePoint(r_col, r_row, nu)
                                        : RCGkrMatMlePoint(r_row, r_col, nu),
                             value};
}

/**
 * G1 — final_eval binding (§3.1 step 4 / Theorem 3.1): the sumcheck chain end
 * gf is DEFINITIONALLY a_at_r·b_at_r of the two bound operand openings; a
 * carried final_eval that differs is rejected deterministically.
 */
[[nodiscard]] inline bool RCGkrCheckFinalEvalBinding(const Fp2& gf, const Fp2& a_at_r,
                                                     const Fp2& b_at_r)
{
    return gkr_field::Eq(gf, gkr_field::Mul(a_at_r, b_at_r));
}

/** Fp3 overload (v7 episode path). */
[[nodiscard]] inline bool RCGkrCheckFinalEvalBinding(const Fp3& gf, const Fp3& a_at_r,
                                                     const Fp3& b_at_r)
{
    return gkr_field::Eq(gf, gkr_field::Mul(a_at_r, b_at_r));
}

/**
 * G2 — layer-claim → trace-column-segment binding (§4.2 output binding): for
 * an ALIGNED segment s (length 2^{|r|}, offset s·2^{|r|}) of a committed
 * column padded to 2^{nu_col}:  ṽ_seg(r) = ṽ_col(r, bits(s)) — the high
 * coordinates are the 0/1-embedded bits of the segment index, evaluated
 * against the SAME commitment (no per-segment column).
 */
[[nodiscard]] inline std::vector<Fp2> RCGkrSegmentPoint(const std::vector<Fp2>& r,
                                                        uint64_t segment_index, uint32_t nu_col)
{
    std::vector<Fp2> p = r;
    p.reserve(nu_col);
    for (size_t b = r.size(); b < nu_col; ++b) {
        p.push_back(((segment_index >> (b - r.size())) & 1u) ? Fp2::One() : Fp2::Zero());
    }
    return p;
}

/**
 * G2 — two-chunk glue (§4.2): a tensor split into two committed chunks is
 * opened as Ỹ(x̂, top) by folding the chunk openings with the top-variable
 * eq-weights: Ỹ(r, r_top) = (1−r_top)·chunk0̃(r) + r_top·chunk1̃(r).
 */
[[nodiscard]] inline Fp2 RCGkrFoldChunkClaims(const Fp2& v0, const Fp2& v1, const Fp2& r_top)
{
    return gkr_field::Add(gkr_field::Mul(gkr_field::Sub(Fp2::One(), r_top), v0),
                          gkr_field::Mul(r_top, v1));
}

/**
 * G5 — residual binding (§4.2, Fwd layers): acc̃(r) = Ỹ(r) + X̃(r) by MLE
 * linearity, where X̃(r) is an opening of the SAME committed X column used as
 * operand A elsewhere. acc is DERIVED — no free residual_mle proof field.
 */
[[nodiscard]] inline Fp2 RCGkrResidualAcc(const Fp2& y_at_r, const Fp2& x_at_r)
{
    return gkr_field::Add(y_at_r, x_at_r);
}

/** G5 — verifier-side check: a carried acc that is not Ỹ(r)+X̃(r) of the two
 *  bound openings is rejected deterministically. */
[[nodiscard]] inline bool RCGkrCheckResidualAcc(const Fp2& acc, const Fp2& y_at_r,
                                                const Fp2& x_at_r)
{
    return gkr_field::Eq(acc, RCGkrResidualAcc(y_at_r, x_at_r));
}

/** Fp3 overloads (v7 episode path). */
[[nodiscard]] inline Fp3 RCGkrResidualAcc(const Fp3& y_at_r, const Fp3& x_at_r)
{
    return gkr_field::Add(y_at_r, x_at_r);
}

[[nodiscard]] inline bool RCGkrCheckResidualAcc(const Fp3& acc, const Fp3& y_at_r,
                                                const Fp3& x_at_r)
{
    return gkr_field::Eq(acc, RCGkrResidualAcc(y_at_r, x_at_r));
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_GKR_EVAL_H
