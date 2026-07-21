// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_GKR_COUPLED_H
#define BTX_MATMUL_MATMUL_V4_RC_GKR_COUPLED_H

#include <arith_uint256.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_gkr_eval.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// Relation (5): SOUND coupled-puzzle verifier (blueprint §7; Wave 3B).
//
// Ground truth (IMMUTABLE, sole authority): RecomputeCoupledPuzzleReference —
// bank pages (template-seeded, nonce-independent), per barrier b:
//   C3.a per-lobe int8 GEMM 1×W · W×W → int64 against the page(s) named by
//        SelectCoupledBankPageIds(b, ℓ) (legacy consensus schedule),
//   C3.a' material exchange: per-lobe int64 rows land at FIXED segment offsets
//        (segment_id = lobe index → cells [ℓ·W, (ℓ+1)·W) of the exchange col),
//   C3.b balanced permutation π_b (public Fisher–Yates over ShaXof(sigma,b)),
//   C3.c butterfly all-to-all mix (pattern b mod 2, mask from sigma),
//   C3.d non-affine Extract (ExtractMXTileInt64 per 32-wide tile),
//   C3.e feed-forward + barrier_root = SHA256d(BARRIER ‖ b ‖ state);
// digest = SHA256d(EPISODE ‖ bank_root ‖ barrier_roots…).
//
// Λ_coup COLUMN LAYOUT (verifier-computable; the proof carries NO layout data —
// §7.1: page schedule, π_b, mix masks, segment ids are all public functions of
// (header, height, params), so forged page IDs / segments are UNEXPRESSIBLE):
//   per barrier b: for ℓ = 0..L−1: [A_{b,ℓ} (W, int8 state slice),
//                                   B_{b,ℓ} (W², int8 bank page),
//                                   Y_{b,ℓ} (W, int64 GEMM row)]
//   then e_b (n, int64 exchange = pre-perm), p_b (n, int64 post-perm),
//        x_b (n, int64 post-mix), s_b (n, int8 extract/state-out).
// All columns live in ONE batched dual-OOD FRI (Thm 2.1).
//
// VERIFIED RELATIONS:
//   R5.gemm (SUCCINCT, the O(work) part): per (b,ℓ) Thaler product sumcheck
//     (§7.2, m=1) with chain-end gf ≡ a_eval·b_eval and Y/A/B openings bound
//     to the batched commitment by the §2.4 eval argument (Thm 2.2/3.1).
//   R5.exchange (committed data-movement, fixed segment IDs): the exchange
//     column opening ẽ_b(r_j, bits(ℓ)) MUST equal the lobe's GEMM claim
//     Ỹ_{b,ℓ}(r_j) — the little-endian index split i = ℓ·W + c makes the
//     fixed segment a subcube restriction, so this one eval-argument claim IS
//     the segment relation (a displaced/forged segment breaks it).
//   R5.perm (public π, §7.3): p̃_b(r_p) must equal Σ_x eq(r_p, π_b(x))·e_b[x],
//     the verifier evaluating the public weight-MLE natively in O(n·ν).
//   R5.mix / R5.extract / R5.roots / R5.bank: grounded by NATIVE re-derivation
//     against the immutable int64 reference — every committed column root must
//     equal the root of the natively re-derived column, barrier roots must be
//     the SHA256d of the grounded state columns, and the digest must equal
//     RecomputeCoupledPuzzleReference byte-for-byte (§7.4–§7.6 in-circuit
//     range/SHA/bank AIRs are the PARKED succinctness gap — same honest
//     over_budget stance as the Wave-2 episode verifier). The Extract relation
//     additionally exercises the dual-α LogUp aggregate over sampled tiles.
//   Backward/checkpoint dependency (§7.5): checkpoint modes are digest-
//     invariant execution policy (non-consensus); the feed-forward data
//     dependency A_{b+1,ℓ} = s_b[ℓW..(ℓ+1)W) is Λ_coup wiring, enforced by the
//     native grounding of both columns from the single state chain.
//
// HONESTY: SOUND but NOT succinct (over_budget=true — the verifier re-runs the
// coupled reference for grounding). The GEMM relation is the part proven
// succinctly. Full coupled succinctness (in-circuit AIRs for perm/mix/Extract/
// SHA + T_R16 range columns against mod-p wraparound) is a follow-on that
// reuses the episode AIR work. Arbiter stays OFF; nMatMulRCCoupledHeight =
// INT32_MAX; ExactReplay remains the consensus authority. Because every
// int-semantics column is grounded natively (never prover-free), the §7.4
// F-wrap mod-p attack has no degree of freedom in THIS variant.
// ============================================================================

namespace matmul::v4::rc {

inline constexpr char kRCGkrCoupledV7Statement[] =
    "Coupled R5 (Wave 3B): ProveWinnerCoupledV7/VerifyWinnerCoupledV7 prove the "
    "ACTUAL coupled computation (RecomputeCoupledPuzzleReference is the sole "
    "immutable authority). GEMM succinct via batched-FRI sumcheck + eval-arg; "
    "exchange = committed fixed-segment opening relation; perm = native public-"
    "pi weight-MLE binding; mix/Extract/barrier-roots/bank = native grounding "
    "(SOUND, over_budget — in-circuit AIRs are the parked succinctness gap). "
    "Never proves toy/unrelated work: claimed digest MUST equal the int64 "
    "coupled reference. Arbiter OFF; nMatMulRCCoupledHeight=INT32_MAX.";

/** One (barrier, lobe) GEMM block. NO (dims, page id, segment id) — those are
 *  Λ_coup outputs the verifier derives natively (forgeries unexpressible). */
struct RCGkrCoupledLobeClaimV7 {
    std::vector<RCGkrSumcheckRound> sumcheck;
    /** c = Ỹ_{b,ℓ}(r_j) — bound to the committed Y column (eval argument). */
    Fp2 c_claim{};
    /** Ã_{b,ℓ}(r_k) — opening of the committed state-slice operand column. */
    Fp2 a_eval{};
    /** B̃_{b,ℓ}(r_k, r_j) — opening of the committed bank-page column. */
    Fp2 b_eval{};
    /** Sumcheck chain end; MUST equal a_eval·b_eval (Thm 3.1). */
    Fp2 final_eval{};
    /** ẽ_b(r_j, bits(ℓ)) — the fixed-segment material-exchange opening; MUST
     *  equal c_claim (checked, then bound by the eval argument). */
    Fp2 exchange_eval{};
};

struct RCGkrCoupledProofV7 {
    uint32_t version{kRCGkrProofVersionV7};
    RCCoupParams params{};
    int32_t height{0};
    uint256 claimed_digest{};
    uint256 pow_bind{};
    uint256 sigma{};
    /** SHA256d(BANK ‖ all page bytes) — must match the native re-derivation. */
    uint256 bank_root{};
    /** Exactly params.barriers roots (F10 omission is structural reject). */
    std::vector<uint256> barrier_roots;
    /** ONE batched dual-OOD FRI over ALL Λ_coup columns + eval-arg f,g. */
    FriBatchProof batch{};
    /** barriers × lobes blocks, row-major (b, ℓ) in Λ_coup order. */
    std::vector<RCGkrCoupledLobeClaimV7> lobes;
    /** Per barrier: p̃_b(r_p) — must equal the native Σ eq(r_p, π_b(x))·e_b[x]. */
    std::vector<Fp2> perm_evals;
    /** Per barrier: x̃_b(r_m) — must equal the native post-mix MLE. */
    std::vector<Fp2> mix_evals;
    RCGkrEvalArgumentProof eval{};
    /** Dual-α Extract LogUp challenges (FS-bound; §5.6). */
    Fp2 logup_alpha1{};
    Fp2 logup_alpha2{};
    double logup_bits{0.0};
    uint256 transcript_hash{};
    /** Native grounding makes this verifier non-succinct by construction. */
    bool over_budget{true};
    std::string note;
};

struct RCGkrCoupledProveResultV7 {
    RCGkrCoupledProofV7 proof;
    RCGkrTiming timing;
};

/** Λ_coup shape helpers (verifier-computable, layout-definitional). */
[[nodiscard]] inline size_t RCGkrCoupledExpectedLobeCount(const RCCoupParams& p)
{
    return static_cast<size_t>(p.barriers) * p.lobes;
}
/** Per barrier: L × (A,B,Y) + exchange + post-perm + post-mix + state-out. */
[[nodiscard]] inline size_t RCGkrCoupledExpectedColumnCount(const RCCoupParams& p)
{
    return static_cast<size_t>(p.barriers) * (3u * static_cast<size_t>(p.lobes) + 4u);
}

/**
 * Coupled R5 prover. REFUSES to prove anything whose claimed_digest does not
 * equal the immutable int64 coupled reference for (header, height, params) —
 * it can never emit a proof of toy/unrelated work. SOUND, over_budget; arbiter
 * stays OFF. `target` binds the §6.1 target check into the FS seed.
 */
[[nodiscard]] RCGkrCoupledProveResultV7 ProveWinnerCoupledV7(
    const CBlockHeader& header, int32_t height, const RCCoupParams& params,
    const arith_uint256& target, const uint256& claimed_digest);

/**
 * Coupled R5 verifier (behind the OFF arbiter). Enumerates Λ_coup natively,
 * grounds every committed column against the immutable reference, verifies the
 * batched FRI + per-lobe sumchecks + eval-argument openings + fixed-segment
 * exchange + public-π permutation binding + dual-α Extract LogUp + barrier-
 * root/bank/digest SHA closure. REJECTS the coupled forgery list (F10/F11 +
 * operand/opening/root/sigma/dims/target/digest forgeries). `why` names the
 * first failing relation. NEVER consensus; ExactReplay stays the arbiter.
 */
[[nodiscard]] bool VerifyWinnerCoupledV7(const RCGkrCoupledProofV7& proof,
                                         const CBlockHeader& header, int32_t height,
                                         const arith_uint256& target,
                                         std::string* why = nullptr);

/**
 * Legacy-format bridge used by ProveWinnerCoupled (matmul_v4_rc_gkr.cpp thin
 * call-site). Runs ProveWinnerCoupledV7 (max target) + a VerifyWinnerCoupledV7
 * self-check; timing.ok=true iff a REAL sound coupled proof was produced and
 * verified. The RCGkrProof body stays empty (the real proof is the v7 coupled
 * format — the v6 container cannot carry it); shrink_note/timing.note say so.
 * Fail-closed (ok=false, note="coupled_digest_mismatch_refuses_unrelated_work")
 * whenever resealed_digest is not the int64 coupled reference digest.
 */
[[nodiscard]] RCGkrProveResult ProveWinnerCoupledLegacyBridge(
    const CBlockHeader& header, int32_t height, const RCCoupParams& params,
    const uint256& resealed_digest);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_GKR_COUPLED_H
