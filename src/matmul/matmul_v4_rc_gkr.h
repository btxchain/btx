// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_GKR_H
#define BTX_MATMUL_MATMUL_V4_RC_GKR_H

#include <arith_uint256.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_distributed.h>
#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_fri_ext3.h>
#include <matmul/matmul_v4_rc_gkr_eval.h>
#include <matmul/matmul_v4_rc_gkr_field.h>
#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_verify_budget.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// ENC_RC Section-2 — winner-only succinct GKR/sumcheck + FRI scaffold.
// Does NOT raise nMatMulRCHeight.
//
// GKR REALITY GUARDRAIL (Amendment v2 — enforce always):
//   REJECT any "HBM proof production-complete" claim until ALL hold:
//     (1) proves the ACTUAL episode (not a synth proxy),
//     (2) is succinct / block-sized,
//     (3) verifies WITHOUT re-running the work,
//     (4) carries a formal ≤2^{-64}-after-grinding bound.
//   This tip is a CODE-COMPLETE SCAFFOLD (Fp3 episode-v7 + REAL FRI + ALL-PHASE
//   real-episode arithmetization + shadow wiring; legacy v6/coupled remain
//   Fp2). It is NOT production-complete / NOT
//   silicon-qualified. Soft over_budget may recommend ExactReplay (M4 shipping)
//   but MUST NOT replace the episode with toy-slice arithmetization.
//
// Consensus today: ε=0 ExactReplay (CheckMatMulProofOfWork_RC) is the arbiter.
// Shadow: BTX_RC_GKR_SHADOW=1 (default) generate+verify, log mismatches, never
// reject. Arbiter cutover is compile-time hard-disabled via
// kRCGkrFormalSoundnessReady (ignores BTX_RC_GKR_ARBITER) and does NOT raise
// height. v7 grounding / prove / verify remain callable for tests.

namespace matmul::v4::rc {

inline constexpr uint32_t kRCGkrProofVersion = 7;
inline constexpr char kRCGkrDomainTag[] = "BTX_RC_GKR_WINNER_V7";
/** Magic for optional out-of-band / cache carriage (not consensus body). */
inline constexpr uint32_t kRCGkrProofMagic = 0x524b4737u; // 'RKG7'

/**
 * Compile-time gate for succinct-proof / arbiter consensus authority.
 *
 * While false, EnvRCGkrArbiterEnabled() always returns false and ignores
 * BTX_RC_GKR_ARBITER — no path may accept GKR as proof-only consensus winner.
 * Does NOT disable: shadow observe, prove/verify APIs, or v7 native re-derivation
 * grounding in VerifyWinnerProofV7 / Coupled V7 (sound by grounding against the
 * int64 reference; ExactReplay remains sole consensus authority).
 *
 * Flip only after formal ≤2^{-64}-after-grind + G1–G5 succinct bindings +
 * external audit. G1–G5 remain OPEN/PARKED until then.
 */
inline constexpr bool kRCGkrFormalSoundnessReady = false;

inline constexpr const char* kRCGkrRealityGuardrail =
    "REJECT HBM/production-complete GKR claims: succinct scaffold uses Fp3+REAL "
    "FRI (episode-v7; legacy v6/coupled remain Fp2) and ALL-PHASE real-episode "
    "arithmetization (QKt/SV/Fwd/Bwd/Wgrad × "
    "rounds; no shrink-to-toy), but is NOT production-complete — require "
    "consensus-dim prove within budget + succinct/block-sized + no-rerun "
    "verify + formal <=2^{-64}-after-grinding bound (see soundness note). "
    "Soft over_budget → VerifyBoundedExactReplay is shrink-to-replayable for "
    "shipping (M4), not shrink-to-toy arithmetization. "
    "NOT production-complete. nMatMulRCHeight=INT32_MAX.";

inline constexpr const char* kRCGkrSoundnessBoundStatement =
    "Winner-only GKR/sumcheck+FRI SCAFFOLD (COMPUTATIONAL aspirational target): "
    "formal <=2^{-64} AFTER PoW grinding is a Stage-I REQUIREMENT. EPISODE-v7 "
    "challenges live in Goldilocks Fp3 (|F|=p^3~2^192; Fp3-codeword FRI, "
    "matmul_v4_rc_fri_ext3); legacy v6/coupled paths remain Fp2 (|F|~2^128); "
    "single Goldilocks is insufficient. MARGIN RESTORATION 2026-07-22 "
    "(SHIPPED): fold Q=116->128 (field-independent) lifted the FRI floor to "
    "76.80; the Fp3 challenge cutover lifts the FS subtotal 72->135.5, so the "
    "composed bound is FRI-query-dominated at ~76.8 (margin ~12.8 over 64, "
    "adequate; clears the 74-bit restored-margin bar). GF(p^2) is NOT a "
    "subfield of GF(p^3): the v7 algebraic layer is uniformly Fp3. "
    "M6/Fable FRI: unique-decoding Q=128, ρ=1/16, g=40 → "
    "Fri3SoundnessBoundBits()=76 (Fp2 stack unchanged for v6/coupled). "
    "DEEP/OOD exact-eval binding CLOSED (FRI v4). "
    "G1–G5 OPEN/PARKED (proof v7): mutation-of-honest forges are NOT soundness "
    "evidence. Missing: PCS openings of A/B/Y at sumcheck points; layer roots "
    "tied to a_fri/b_fri/trace_fri segments; verifier-defined Extract AIR "
    "(vacuous w≡t LogUp); bank page openings under bank_root. Independent "
    "malicious constructors currently ACCEPT (see ProveIndepMalicious*). "
    "Coupled: real lobe-GEMM + barrier-Extract format (no toy stand-in) but "
    "bindings incomplete. External crypto audit MANDATORY before arbiter. "
    "Merkle q=8 is DoS PREFILTER ONLY. ExactReplay remains consensus arbiter "
    "(kRCGkrFormalSoundnessReady=false ⇒ EnvRCGkrArbiterEnabled ignores "
    "BTX_RC_GKR_ARBITER). nMatMulRCHeight=INT32_MAX.";

inline constexpr const char* kRCGkrSoundnessStatement = kRCGkrSoundnessBoundStatement;
inline constexpr const char* kRCGkrSoundnessNote = kRCGkrSoundnessBoundStatement;

inline constexpr const char* kRCGkrE5Decision =
    "DECIDED: winner-only GKR/sumcheck direction. Fraud-proof deferred. Shrink/"
    "ExactReplay is the production fallback until Reality Guardrail gates close.";

inline constexpr const char* kRCGkrMerkleQ8PrefilterStatement =
    "kRCSpotCheckQueries=8 Merkle leaf sampling is a bandwidth DoS PREFILTER "
    "ONLY. It is NOT a soundness claim and MUST NOT be sole consensus validity "
    "(P2.1 f^q grinding). Production soundness requires Reality Guardrail "
    "gates or ε=0 ExactReplay dispute/fallback.";

inline constexpr const char* kRCGkrHbmParkStatement =
    "HBM-scale winner GKR is NOT production-complete under Reality Guardrail. "
    "Consensus-dim ALL-PHASE prove may soft-over_budget on CPU (M4 shipping → "
    "ExactReplay); that is shrink-to-replayable, not shrink-to-toy. PARK HBM "
    "GKR as production arbiter until budgets close; ship both verifiers and "
    "keep ε=0 ExactReplay as consensus default.";

/** Coupled path (Wave 3B, superseding the fail-closed stand-in): the sound
 *  coupled-R5 arithmetization lives in matmul_v4_rc_gkr_coupled.{h,cpp}
 *  (ProveWinnerCoupledV7 / VerifyWinnerCoupledV7). ProveWinnerCoupled now
 *  delegates there; it still NEVER proves toy/unrelated work (the bridge
 *  refuses any digest that is not the int64 coupled reference digest).
 *  Arbiter stays OFF; ExactReplay remains the consensus authority. */
inline constexpr const char* kRCGkrCoupledArithStatement =
    "ProveWinnerCoupled: delegates to the sound coupled-R5 v7 prover "
    "(matmul_v4_rc_gkr_coupled). GEMM succinct via batched-FRI sumcheck + "
    "eval argument; page-selection/exchange/perm/mix/Extract/roots grounded "
    "natively vs the immutable int64 reference (SOUND, over_budget). Never "
    "emits a toy/episode stand-in proof of unrelated work. "
    "Arbiter hard-disabled (kRCGkrFormalSoundnessReady=false).";

/**
 * Honest G1–G5 status — CLOSED only after independent malicious proofs REJECT
 * under PCS openings + verifier-defined Extract (see construction doc).
 * Mutation-of-honest suites prove transcript integrity only.
 */
inline constexpr const char* kRCGkrG1G5ClosedStatement =
    "G1–G5 OPEN/PARKED (proof v7): mutation forges ≠ soundness. Missing "
    "relations: (G1) a_at_r/b_at_r unbound to a_fri/b_fri at sumcheck point; "
    "(G2) claim/y_root unbound to trace_fri segment openings; (G3) prover "
    "manufactures identical witness/table keys (Theorem 5.1 vacuity); "
    "(G4) extract_out_commit is FS-only; (G5) residual algebra without column "
    "wiring. Arbiter hard-disabled; ExactReplay sole consensus accept. "
    "External crypto audit mandatory before any CLOSED claim.";

/** Alias kept for call sites that still name the closed statement. */
inline constexpr const char* kRCGkrG1G5StatusStatement = kRCGkrG1G5ClosedStatement;

inline constexpr const char* kRCGkrShadowStatement =
    "BTX_RC_GKR_SHADOW=1 (default): generate+verify winner proof in shadow; "
    "mismatch LogWarning; NEVER rejects CheckMatMulProofOfWork_RC. "
    "kRCGkrFormalSoundnessReady=false: EnvRCGkrArbiterEnabled ignores "
    "BTX_RC_GKR_ARBITER (no proof-only consensus authority); ExactReplay "
    "decides. Does NOT raise height.";

using gkr_field::Fp;
using gkr_field::Fp2;
using gkr_field::Fp3;

/** Layer kind in the ALL-PHASE real-episode / coupled arithmetization. */
enum class RCGkrLayerKind : uint32_t {
    GemmPhase1QKt = 1, // Q·Kᵀ product layer
    GemmPhase1SV = 2,  // S·V product layer
    GemmPhase2Fwd = 3, // forward residual GEMM
    GemmPhase2Bwd = 4, // backward GEMM
    GemmPhase2Wgrad = 5,
    /** Coupled: lobe row × bank page ExactGemm (1×W)·(W×W). */
    CoupLobeGemm = 10,
    /** Coupled: barrier non-affine Extract on full active state (LogUp only). */
    CoupBarrierExtract = 11,
    SynthGemmDeprecated = 100, // DEPRECATED synth proxy only
};

// ============================================================================
// v7 FOUNDATION substrate (blueprint §2–4, §6.3; arbiter stays OFF).
// The v6 proof/verifier below remains for the shadow scaffold until the
// integration wave lands ProveFromLayout / layout-driven VerifyWinnerProof.
// ============================================================================

inline constexpr uint32_t kRCGkrProofVersionV7 = 7;
inline constexpr char kRCGkrDomainTagV7[] = "BTX_RC_GKR_WINNER_V7";
/** Bumped whenever the FS absorption schedule changes shape. Bound into the
 *  transcript BEFORE any challenge (blueprint item 7).
 *  v2 (2026-07-22): episode-v7 challenge field Fp2 → Fp3 — every v7 FS
 *  absorb/challenge is now 24-byte Fp3, so all episode-v7 transcripts and
 *  digests deliberately diverge from the v1 (Fp2) goldens. */
inline constexpr uint32_t kRCGkrFsProfileVersionV7 = 2;

/**
 * κ — the 2-adicity wall. Goldilocks F_p^× has max power-of-two subgroup 2^32;
 * with FRI blowup 16 a single committed column caps at 2^28 coefficients
 * (LDE 16·2^28 = 2^32). The consensus trace is 2^33.39 cells, and a single
 * QKt output alone is 2^28.58, so the trace MUST be split into multiple
 * columns — a single concatenated trace vector cannot even be committed.
 */
inline constexpr uint32_t kRCGkrColumnMaxLog2 = 28;
inline constexpr uint64_t kRCGkrColumnMaxCoeffs = uint64_t{1} << kRCGkrColumnMaxLog2;
static_assert((uint64_t{16} << kRCGkrColumnMaxLog2) == (uint64_t{1} << 32),
              "blowup*kappa must equal the Goldilocks 2-adicity cap 2^32");

/** Distinct tensor identities of the canonical layout Λ(params) (§4.1).
 *  Operand/extract tensors are committed ONCE and referenced per use
 *  (transposed uses read the same column via the free-transpose fact §1.2). */
enum class RCGkrTensor : uint8_t {
    Q = 0,   // expanded operand, per round: n_q × d_head
    K = 1,   // expanded operand, per round: n_ctx × d_head (QKt reads Kᵀ)
    V = 2,   // expanded operand, per round: n_ctx × d_head
    S = 3,   // extract_out of QKt, per round: n_q × n_ctx
    Z = 4,   // extract_out of SV, per round: n_q × d_head
    X = 5,   // layer 0 expanded; layer l+1 = extract_out of Fwd(l): b_seq × d_model
    W = 6,   // expanded operand, per (round, l): d_model × d_model
    G = 7,   // layer L expanded; layer l = extract_out of Bwd(l): b_seq × d_model
    D = 8,   // extract_out of Wgrad(l): d_model × d_model
    YQKt = 9,  // int64 GEMM output (T-column), n_q × n_ctx
    YSV = 10,  // int64 GEMM output, n_q × d_head
    YFwd = 11, // int64 GEMM output (pre-residual), b_seq × d_model
    YBwd = 12, // int64 GEMM output, b_seq × d_model
    YWgrad = 13, // int64 GEMM output, d_model × d_model
};

/** One committed column = one κ-bounded chunk of one tensor. */
struct RCGkrColumnInfo {
    uint32_t id{0};
    RCGkrTensor tensor{RCGkrTensor::Q};
    uint32_t round{0};
    /** Layer index for X/W/G/D/Y*-tensors (X: 0..L, G: 0..L, W/D: 0..L−1); 0 otherwise. */
    uint32_t layer{0};
    /** Logical row-major matrix dims of the FULL tensor this chunk belongs to. */
    uint32_t rows{0};
    uint32_t cols{0};
    /** Chunk split at κ = kRCGkrColumnMaxCoeffs (ceil(cells/κ) chunks). */
    uint32_t chunk{0};
    uint32_t n_chunks{1};
    uint64_t chunk_offset{0}; // first cell covered (row-major)
    uint64_t len{0};          // logical cells in this chunk (= FRI degree bound)
    /** true: int64 GEMM output cells (T-column); false: int8 cells (O-column). */
    bool int64_cells{false};
};

/** Reference to a tensor's column range as a GEMM operand (§1.2: transpose is
 *  free — M̃ᵀ(r,s) = M̃(s,r) — so transposed uses carry a flag, not a copy). */
struct RCGkrOperandRef {
    uint32_t first_column{0};
    uint32_t n_chunks{1};
    bool transpose{false};
};

/** One layer of the canonical sequence Λ(params). The VERIFIER enumerates
 *  these (§4.1): (kind, round, layer, m, n, k) and all operand identities are
 *  OUTPUTS of the layout, never prover data — order forgeries (F8/F9) are
 *  unexpressible. */
struct RCGkrLayerSpec {
    RCGkrLayerKind kind{RCGkrLayerKind::GemmPhase1QKt};
    uint32_t round{0};
    uint32_t layer{0};
    uint32_t m{0};
    uint32_t n{0};
    uint32_t k{0};
    RCGkrOperandRef a{};
    RCGkrOperandRef b{};
    /** GEMM output Y chunk columns (int64 T-columns). */
    uint32_t y_first_column{0};
    uint32_t y_chunks{1};
    /** extract_out tensor columns (int8 O-columns) produced by this layer. */
    uint32_t out_first_column{0};
    uint32_t out_chunks{1};
    /** Fwd only: residual operand column range (== a; G5: acc = Y + X_l at
     *  evaluation points, no separately committed extract_in). −1 otherwise. */
    int32_t residual_first_column{-1};
};

struct RCGkrLayout {
    RCEpisodeParams params{};
    std::vector<RCGkrColumnInfo> columns;
    std::vector<RCGkrLayerSpec> layers;
    uint64_t trace_cells{0};   // Σ Y cells (N_Y; 11,274,551,296 at consensus dims)
    uint64_t operand_cells{0}; // Σ O-column cells (expanded operands + extract outs)
    uint64_t total_cells{0};
};

/**
 * Canonical, verifier-computable trace layout Λ(params) (§4.1, §6.3):
 * enumerates the exact layer sequence QKt → SV → Fwd(0..L−1) →
 * [Bwd(l), Wgrad(l)] for l = L−1..0, per round, and assigns every distinct
 * tensor exactly one committed column range (chunked at κ = 2^28).
 * Requires ValidateRCEpisodeParams(params).
 */
[[nodiscard]] RCGkrLayout RCGkrTraceLayout(const RCEpisodeParams& params);

/**
 * v7 Fiat–Shamir seed (blueprint item 7): binds proof version + domain tag +
 * FS profile version, the FULL header (every wire field + GetHash()), the
 * nonce-bound sigma, height, the exact episode params, target AND nBits,
 * claimed digest + pow_bind, and all round roots — BEFORE any challenge is
 * drawn. Use as the fs_seed of FriBatchCommit / the v7 transcript. Absorbing
 * unrelated roots is insufficient (§4.3 insufficiency lemma / forgery F0).
 */
[[nodiscard]] uint256 RCGkrFsSeedV7(const CBlockHeader& header, int32_t height,
                                    const RCEpisodeParams& params,
                                    const arith_uint256& target,
                                    const uint256& claimed_digest,
                                    const uint256& episode_sigma,
                                    const std::vector<uint256>& round_roots);

/** Coupled-puzzle variant: binds the exact RCCoupParams + barrier roots under
 *  a distinct sub-domain label (episode/coupled transcripts can never collide). */
[[nodiscard]] uint256 RCGkrFsSeedV7Coupled(const CBlockHeader& header, int32_t height,
                                           const RCCoupParams& params,
                                           const RCCoupOptions& options,
                                           const arith_uint256& target,
                                           const uint256& claimed_digest,
                                           const uint256& sigma,
                                           const std::vector<uint256>& barrier_roots);


/** Soft budgets for the Section-2 scaffold (CPU toy/medium). Not silicon.
 *  Verify ceiling is Stage-I interval-fraction (see matmul_v4_rc_verify_budget.h). */
inline constexpr double kRCGkrMediumProveBudgetS = 2.0;
inline constexpr double kRCGkrVerifyBudgetS = kRCHappyPathVerifyBudgetS;
inline constexpr size_t kRCGkrProofBytesBudget = 3 * 1024 * 1024; // 3 MiB soft (DEEP+A/B FRI)

/** Hard reject-before-work limits (DoS). Soft budget remains kRCGkrProofBytesBudget.
 *  Toy ALL-PHASE proofs with DEEP+A/B FRI are ~14 MiB today; hard cap must sit above
 *  that while still bounding allocation. */
inline constexpr size_t kRCGkrMaxProofBytesHard = 32 * 1024 * 1024; // 32 MiB
inline constexpr uint32_t kRCGkrMaxLayersHard = 256;
inline constexpr uint32_t kRCGkrMaxSumcheckRoundsHard = 64;
inline constexpr uint32_t kRCGkrMaxRoundSeedsHard = 64;

/** One sumcheck round over Fp2: g(0), g(1), g(2) (deg-2 product). Legacy
 *  v6/coupled paths only — the episode-v7 path uses RCGkrSumcheckRound3. */
struct RCGkrSumcheckRound {
    Fp2 eval0{};
    Fp2 eval1{};
    Fp2 eval2{};
};

/** One sumcheck round over Fp3 (episode-v7 path; |F| = p^3 ≈ 2^192). */
struct RCGkrSumcheckRound3 {
    Fp3 eval0{};
    Fp3 eval1{};
    Fp3 eval2{};
};

struct RCGkrLayerClaim {
    RCGkrLayerKind kind{RCGkrLayerKind::GemmPhase1QKt};
    uint32_t round{0};
    uint32_t layer{0};
    uint32_t m{0};
    uint32_t n{0};
    uint32_t k{0};
    /** Product sumcheck claim = MLE(Y_gemm). */
    Fp2 claim{};
    /**
     * G5: for Fwd, MLE(extract_in) must equal claim + residual_mle.
     * Non-Fwd: residual_mle=0 and acc_claim=claim.
     */
    Fp2 residual_mle{};
    Fp2 acc_claim{};
    /** G4: SHA256d commitment to extract_out bytes (cross-layer link). */
    uint256 extract_out_commit{};
    /** G1: Merkle roots of A and B wires (commit-then-challenge). */
    uint256 a_root{};
    uint256 b_root{};
    /** G2: commitment to this layer's Y_gemm (trace segment). */
    uint256 y_root{};
    /**
     * G1: folded A/B openings at sumcheck point rk — must satisfy
     * final_eval = a_at_r * b_at_r.
     */
    Fp2 a_at_r{};
    Fp2 b_at_r{};
    /** Coupled lobe-GEMM: bank page id (legacy: (barrier+lobe)%bank_pages). */
    uint32_t page_id{0};
    /** G3: Haböck table multiplicity for this layer's tiles (must be 1). */
    uint32_t table_multiplicity{1};
    std::vector<RCGkrSumcheckRound> sumcheck;
    Fp2 final_eval{};
};

/**
 * Succinct proof: NO per-tile Extract raw payloads.
 * LogUp aggregate + FRI openings only.
 */
struct RCGkrProof {
    uint32_t version{kRCGkrProofVersion};
    uint256 claimed_digest{};
    /** PoW-grinding resistance: FS absorbs this PoW-bind tag after digest. */
    uint256 pow_bind{};
    /** Episode shape public inputs (actual params; no shrink-to-toy). */
    RCEpisodeParams episode{};
    /**
     * Coupled mode: proof arithmetizes RCCoupParams (not RCEpisodeParams).
     * When true, round_roots = barrier_roots and coup/bank_root are binding.
     */
    bool coupled{false};
    RCCoupParams coup{};
    /** Coupled bank commitment (SHA256 over epoch pages). */
    uint256 bank_root{};
    /**
     * Round/barrier seeds: episode seed[0]=Sha256TaggedU32(ROUND,sigma,0);
     * seed[r]=Sha256TaggedU32(ROUND, round_roots[r-1], r).
     * Coupled: seed[b]=Sha256TaggedU32(BARRIER,sigma,b).
     */
    std::vector<uint256> round_seeds;
    /** Round merkle roots (tile-tree) or coupled barrier_roots. */
    std::vector<uint256> round_roots;
    /** DeriveSigma(header) at prove time — verify re-derives seed[0] from this. */
    uint256 episode_sigma{};
    /** G3: global Haböck multiplicity bound (1:1 tile keys). */
    uint32_t table_multiplicity{1};
    std::vector<RCGkrLayerClaim> layers;
    /**
     * G3 Haböck LogUp (ePrint 2022/1530):
     *   witness keys w_i = Hash(meta, in, out)
     *   table keys   t_i = Hash(meta, in, Extract(in))  // virtual Extract table
     *   Σ 1/(α−w_i) = Σ 1/(α−t_i)  (here enforced by w≡t + inverse column)
     * lookup_logup_sum = Σ inv_i with inv_i = 1/(α−t_i), proven via Haböck
     * I(1) layer-0 Merkle opening at z=1 + R≡0.
     */
    Fp2 lookup_logup_sum{};
    Fp2 lookup_table_sum{}; // must equal lookup_logup_sum
    Fp2 logup_alpha{};
    /** Witness LogUp keys FRI. */
    FriProof lookup_fri{};
    /** Virtual Extract-table keys FRI (must match lookup_fri root/DEEP). */
    FriProof table_fri{};
    /** inv_i = 1/(α − t_i); Haböck I(1) layer-0 Merkle at z=1 binds sum. */
    FriProof logup_inv_fri{};
    /** R_i = inv_i·(α−t_i)−1; must be the zero polynomial. */
    FriProof logup_r_fri{};
    /** FRI commit of concatenated GEMM output wires (Y_gemm coeffs). */
    FriProof trace_fri{};
    /** G1: FRI commit of concatenated A operands across layers. */
    FriProof a_fri{};
    /** G1: FRI commit of concatenated B operands across layers. */
    FriProof b_fri{};
    uint256 transcript_hash{};
    /** Soft budget exceeded → recommend ExactReplay (shipping); not toy swap. */
    bool over_budget{false};
    std::string shrink_note;

    // --- DEPRECATED synth-only fields (empty on real-episode path) ---
    DistSynthShape shape{};
    std::vector<int64_t> claimed_Y;
    std::vector<int8_t> claimed_extract;
    std::vector<RCGkrSumcheckRound> sumcheck;
    std::vector<RCGkrSumcheckRound> gemm_sumcheck;
    Fp2 final_eval{};
    Fp2 gemm_final_eval{};
};

struct RCGkrTiming {
    double prove_s{0};
    double verify_s{0};
    size_t proof_bytes{0};
    size_t peak_rss_kib{0};
    bool ok{false};
    bool over_budget{false};
    bool used_shrink_fallback{false};
    std::string note;
};

struct RCGkrProveResult {
    RCGkrProof proof;
    RCGkrTiming timing;
};

// ============================================================================
// v7 PROOF + LAYOUT-DRIVEN VERIFIER (blueprint §10; arbiter stays OFF).
//
// The v7 verifier composes the Wave-1 substrate into a SOUND episode verifier
// that REJECTS the §9 forgery list (v6 accepts F0 w.p. 1). Composition:
//   R1  A/B opening → final_eval: per-layer Thaler product sumcheck
//       (VerifyProductK) with the chain-end gf bound by final_eval = a·b, where
//       a_eval=Ã(r_i,r_k), b_eval=B̃(r_k,r_j) are openings of the COMMITTED
//       operand columns via the batched-FRI eval argument (§2.4). A prover-
//       supplied final_eval with no opening cannot pass (Thm 3.1).
//   R2  claim-to-trace: c_ℓ = Ỹ(r_i,r_j) is an opening of the committed Y
//       column (never a free proof field); wiring is Λ-definitional.
//   R3  Extract: dual-α LogUp aggregate over the tile sub-relations
//       (LogUpDualAlphaVerify), plus native byte-exactness vs the immutable
//       ExtractMXTileInt64 reference (the §5.7/§6.3 in-circuit ChaCha/SHA/
//       tile-tree AIRs are the PARKED succinctness gap — see the report).
//   R4  canonical sequence: the VERIFIER enumerates Λ(params) itself; the proof
//       carries no per-layer (kind,round,dims) — reorder/repeat/omit forgeries
//       are unexpressible (Thm 4.2), deterministic reject.
//   §6.3 round-root binding: round_roots are recomputed by the RoundMerkleStream
//       tile-tree over the (ground-truth-grounded) committed extract columns and
//       must equal the proof's — this is what closes the F0 headline that v6
//       leaves open (per-layer root absorption binds nothing, §4.3).
//
// SUCCINCTNESS (Wave 3A): the operand-expansion / Extract / tile-tree GROUNDING
// is now done by IN-CIRCUIT AIRs over the committed columns — MxExpandAir
// (§5.7), the Extract sampler AIR over ALL tiles (§5.4) + dual-α LogUp (§5.6),
// and the tile-tree SHA AIR (§6.3) — NOT by re-running the int64 reference. The
// verifier derives only the PUBLIC seeds / prf keys natively (§4.2/§6.1). At toy
// dims this clears the Stage-I happy-path verify budget (over_budget=false). The
// witness columns are materialized (carried + FRI-bound); the residual toward
// verifier-sublinearity is the DEEP/quotient opening of the AIR constraint
// polynomial (open at Q points instead of every row) — at consensus dims the
// LogUp is ≈2^43 rows and stays PARKED (§11). Arbiter stays OFF,
// nMatMulRCHeight=INT32_MAX, ExactReplay remains sole authority.
// ============================================================================

/** One layer's v7 sumcheck block. NO (kind,round,dims) — those are Λ outputs.
 *  UNIFORMLY Fp3 (2026-07-22 cutover): every claim/opening on this path is
 *  combined with the Fri3 codeword algebra, and GF(p^2) is NOT a subfield of
 *  GF(p^3) — mixed-field terms are unexpressible, so the whole layer is Fp3. */
struct RCGkrLayerClaimV7 {
    std::vector<RCGkrSumcheckRound3> sumcheck;
    /** c_ℓ = Ỹ(r_i,r_j) — bound to the committed Y column by the eval argument. */
    Fp3 c_claim{};
    /** a_ℓ = Ã(r_i,r_k) — opening of the committed A column. */
    Fp3 a_eval{};
    /** b_ℓ = B̃(r_k,r_j) — opening of the committed B column. */
    Fp3 b_eval{};
    /** sumcheck chain-end gf; MUST equal a_eval·b_eval (Thm 3.1). */
    Fp3 final_eval{};
};

/**
 * Committed per-layer witness columns (§2.1 A-columns), carried so the SUCCINCT
 * verifier can run the in-circuit AIRs (Extract / MxExpand / tile-tree) over the
 * committed data WITHOUT re-running the int64 reference. Each column is bound to
 * its batched-FRI root (FriBatchColumnRoot); a tampered witness column fails the
 * commitment binding, and a *consistent* forged column fails the AIR that
 * constrains it (Extract sampler / dequant / tile-tree). Field-embedded int8/
 * int64 values keep byte-exactness with the reference oracle.
 */
struct RCGkrV7WireWitness {
    RCGkrLayerKind kind{};
    uint32_t round{0};
    uint32_t layer{0};
    uint32_t m{0}, n{0}, k{0};
    std::vector<int8_t> A;            // operand A (int8), m×k
    std::vector<int8_t> B;            // operand B (int8), k×n
    std::vector<int64_t> Y;           // GEMM product (int64), m×n
    std::vector<int64_t> extract_in;  // pre-Extract accumulator (int64), m×n
    std::vector<int8_t> extract_out;  // Extract output (int8), m×n
};

struct RCGkrProofV7 {
    uint32_t version{kRCGkrProofVersionV7};
    RCEpisodeParams episode{};
    int32_t height{0};
    uint256 claimed_digest{};
    uint256 pow_bind{};
    uint256 episode_sigma{};
    std::vector<uint256> round_seeds;
    std::vector<uint256> round_roots;
    /** ONE batched Fp3 FRI over ALL columns (per-layer A,B,Y,extract) +
     *  eval-arg f,g. The integer witness embeds into Fp3 as c0=value,
     *  c1=c2=0; challenges live in |F| = p^3 ≈ 2^192. */
    Fri3BatchProof batch{};
    std::vector<RCGkrLayerClaimV7> layers;
    /** Committed witness columns for the in-circuit AIRs (bound to `batch`). */
    std::vector<RCGkrV7WireWitness> wires;
    RCGkrEvalArgumentProof3 eval{};
    /** Dual-α Extract LogUp challenges (FS-bound; §5.6), drawn from Fp3. */
    Fp3 logup_alpha1{};
    Fp3 logup_alpha2{};
    double logup_bits{0.0};
    /** SUCCINCT episode-verify wall (in-circuit AIRs, no reference re-run). */
    double verify_s{0.0};
    uint256 transcript_hash{};
    bool over_budget{true};
    std::string note;
};

struct RCGkrProveResultV7 {
    RCGkrProofV7 proof;
    RCGkrTiming timing;
};

/**
 * v7 prover: ALL-PHASE arithmetization of the ACTUAL episode, composed into the
 * batched FRI + per-layer sumcheck + eval argument + dual-α LogUp. PARKED /
 * over_budget; does NOT touch consensus. `target` binds the §6.1 target check.
 */
[[nodiscard]] RCGkrProveResultV7 ProveWinnerEpisodeV7(const CBlockHeader& header,
                                                      const RCEpisodeParams& params, int32_t height,
                                                      const arith_uint256& target,
                                                      const uint256& claimed_digest);

/**
 * v7 layout-driven verifier (behind the OFF arbiter). Enumerates Λ(params),
 * verifies the batched FRI, binds every committed column to the immutable
 * reference, checks the per-layer sumcheck + eval-argument openings + gf=a·b,
 * the dual-α Extract LogUp, and the RoundMerkleStream round-root binding.
 * REJECTS the entire §9 forgery list (v6 accepts F0). `why` names the first
 * failing relation. NEVER consensus; ExactReplay stays the arbiter.
 */
[[nodiscard]] bool VerifyWinnerProofV7(const RCGkrProofV7& proof, const CBlockHeader& header,
                                       int32_t height, const arith_uint256& target,
                                       std::string* why = nullptr,
                                       RCGkrTiming* out_timing = nullptr);

/**
 * F3: bounded wire/payload accounting for the witness-carried v7 scaffold.
 * Returns kRCGkrMaxProofBytesHard+1 when a structural cap or the hard byte cap
 * is exceeded (reject-before-work). Saturating; the carried A/B/Y/extract
 * witness dominates. Admission estimate until a canonical v7 serializer lands.
 */
[[nodiscard]] size_t EstimateRCGkrProofV7PayloadBytes(const RCGkrProofV7& proof);

// ============================================================================
// G1–G5 IN-CIRCUIT RELATIONS (integration wave, 2026-07-22).
//
// The four finite-field constructions (I: batched multilinear evaluation
// opening; II: Extract composition polynomial; III: fixed-reference-vector
// LogUp membership; IV: copy/permutation wiring) are wired into
// VerifyWinnerProofV7 as the in-circuit relations G1–G5, so each winner-proof
// relation is CHECKED by a polynomial identity over the committed columns
// rather than grounded solely by native int64 re-derivation:
//
//   G1  operand openings a_at_r/b_at_r bound to the committed A/B columns
//       (Construction I matrix-opening claim + final-eval binding) AND each
//       committed LEAF operand bound to its Λ MxExpand PRF expansion.
//   G2  each layer claim c_ℓ bound to the committed trace-column segment
//       (Construction I segment point → Ỹ(r) == c_claim).
//   G3  the prover-manufactured lookup is REPLACED by Construction II's Extract
//       composition polynomial (Comp == 0 over every tile) + Construction III's
//       fixed-reference-vector membership (canonical T_M/T_X regenerated, not
//       prover-chosen) + the verifier-defined Extract sampler out-binding.
//   G4  extract_out(L) == input(L+1) (and the §6.3 round-root↔stream binding)
//       via Construction IV — the DUAL-challenge grand product is enforced for
//       transposed copies; the single-challenge form (only 60 bits post-grind)
//       is UNREACHABLE on this path.
//   G5  the Fwd residual accumulator acc = claim + X̃(pt) (and extract_in == Y
//       for the non-residual layers) via Construction I's residual binder.
//
// This stays STRICTLY behind the OFF arbiter — VerifyWinnerProofV7 is never
// consensus-authoritative; ExactReplay remains the sole authority. The relation
// gate runs AFTER the existing §5.4/§5.7/§6.3 native grounding so it never
// changes which relation an already-rejected forgery first fails; it is a
// construction-expressed re-derivation of the SAME soundness, plus the genuinely
// new opening/segment/wiring/residual bindings.
// ============================================================================

/** Which in-circuit relation a winner-proof check belongs to. */
enum class RCGkrRelation : uint8_t { G1 = 1, G2 = 2, G3 = 3, G4 = 4, G5 = 5 };

struct RCGkrRelationsResult {
    bool ok{false};
    /** First failing relation reason, prefixed "v7:g<N>:<detail>" (empty on ok). */
    std::string failure;
    RCGkrRelation first_failing{RCGkrRelation::G1};
    uint64_t n_tiles{0};
    uint64_t n_chain_wirings{0};
};

/**
 * Run the G1–G5 in-circuit relations over `proof` STANDALONE (independent of the
 * native §5 grounding), re-deriving the sumcheck points and FS challenges from
 * the proof itself. Returns ok iff every relation's polynomial identity holds.
 * Used by VerifyWinnerProofV7 (defense-in-depth gate) and by the integration
 * red-team, which feeds internally-consistent forgeries and asserts each rejects
 * at its "v7:g<N>:" relation — i.e. the constructions catch the forgery, NOT
 * only the native re-derivation. NEVER consensus; arbiter stays OFF.
 */
[[nodiscard]] RCGkrRelationsResult CheckWinnerProofRelationsV7(
    const RCGkrProofV7& proof, const CBlockHeader& header, int32_t height,
    const arith_uint256& target);

/** Thin bool wrapper for tests: true iff every G1–G5 relation holds; `why`
 *  receives the first failing "v7:g<N>:*" relation. */
[[nodiscard]] bool VerifyWinnerRelationsV7ForTest(const RCGkrProofV7& proof,
                                                  const CBlockHeader& header, int32_t height,
                                                  const arith_uint256& target,
                                                  std::string* why = nullptr);

// ---------------------------------------------------------------------------
// COMPOSED separation bound across the four constructions + batched-FRI backend
// (integration accounting, PARAMETRIC in the FRI proximity bound). All values
// are −log2(acceptance probability), post the g = 40 grinding convention.
//
// 2026-07-22 Fp3 CHALLENGE CUTOVER — SHIPPED STATE (Q = 128, Fp3 challenges
// on the EPISODE-v7 path). The Q = 116 → 128 lift (field-independent) had
// already raised the FRI floor to 76.80; this wave completes the margin
// restoration by moving the ENTIRE episode-v7 algebraic layer to the Fp3
// codeword FRI (matmul_v4_rc_fri_ext3.{h,cpp}) — batch RLC λ / DEEP weights
// w1,w2 / OOD z1,z2 / eval μ / sumcheck r,ri,rj / LogUp α / wiring ρ,β,γ all
// draw from |F| = p^3 ≈ 2^192. The FS subtotal lifts ≈ 72 → ≈ 135.5, so the
// composed bound becomes FRI-QUERY-dominated at ≈ 76.8 (margin ≈ 12.8 over
// 2^-64, clearing the ≥ 74-bit restored-margin bar).
//
// GF(p^2) is NOT a subfield of GF(p^3) (2 ∤ 3): no Fp2 value may be combined
// with an Fp3 value, which is why the cutover is uniform across the v7
// episode layer. The legacy v6 (RCGkrProof) and coupled-V7 paths still run
// Fp2 (their FS terms keep the F_{p^2} values recorded per-constant below);
// they are a scoped follow-on.
// ---------------------------------------------------------------------------

/** log2 of the SHIPPED episode-v7 challenge field K = F_{p^3}: 3·log2(p),
 *  p = 2^64−2^32+1. */
inline constexpr double kRCGkrChallengeFieldBits = 191.99999999899;
/** Legacy Fp2 challenge-field bits (v6 / coupled paths), for the record. */
inline constexpr double kRCGkrChallengeFieldBitsFp2 = 127.99999999932;
/** Alias retained from the deferred-follow-on era (now the shipped value). */
inline constexpr double kRCGkrChallengeFieldBitsFp3 = kRCGkrChallengeFieldBits;
/** Construction II composition polynomial (n_slots ≤ 256): 3·log2 p − 8 − 40
 *  = 144 (legacy Fp2 value: 80). */
inline constexpr double kRCGkrCompositionSepBits = 144.0;
/** Construction III dual-α fixed-reference-vector membership over Fp3 (§5.6):
 *  256 (legacy Fp2 value: 128). */
inline constexpr double kRCGkrLookupSepBits = 256.0;
/** Construction IV equality (copy) at the κ = 2^28 column cap: 192 − log2(28)
 *  − 40 = 147.19 (legacy Fp2 value: 83.19). */
inline constexpr double kRCGkrWiringEqualitySepBits = 147.19;
/** Construction IV grand product, DUAL challenge, N = 2^28: 2·(192−28) − 40
 *  = 288 (legacy Fp2 value: 160). */
inline constexpr double kRCGkrWiringPermutationDualSepBits = 288.0;
/** Construction IV grand product, SINGLE challenge, N = 2^28: (192−28) − 40 =
 *  124 over Fp3. Over Fp2 this was 60 — BELOW the 64-bit target — which is
 *  the origin of the dual mandate. The single form REMAINS FORBIDDEN on the
 *  ship path (dual is mandatory, structurally enforced by G4): the mandate is
 *  structural and is NOT relaxed by the field lift. */
inline constexpr double kRCGkrWiringPermutationSingleSepBits = 124.0;
/** Whole-protocol Fiat–Shamir subtotal × 2^40 grinding (all sumcheck rounds +
 *  RLC/DEEP weights; Theorem 8.1 line over |F_{p^3}| ≈ 2^192): pre-grind
 *  Σ ≈ 2^-175.5 ⇒ 135.5 post-grind — now ≈ 59 bits ABOVE the 76.80 FRI query
 *  floor, so it is no longer the binding term. (Legacy Fp2 value: 72, which
 *  capped the composed bound at ≈ 71.9.) */
inline constexpr double kRCGkrFsSubtotalSepBits = 135.5;
/** SHA256d Merkle/transcript bindings vs a 2^40-query adversary
 *  (computational; field-independent). */
inline constexpr double kRCGkrShaSepBits = 88.0;
/** FRI proximity term. The integration rides the SOUND v5 half-domain fold; at
 *  Q = kRCFriNumQueries = 128 the fold's own proximity soundness is
 *  128·log2(32/17) − 40 = 76.80 (= `Fri3SoundnessBoundBits()` real value; the
 *  integer helper floors to 76). This term is FIELD-INDEPENDENT (query
 *  repetitions). With the Fp3 FS subtotal (135.5) far above it, this 76.80 is
 *  now the composed-bound floor (fri_dominated). Historical Q = 116 value:
 *  65.85. */
inline constexpr double kRCGkrFriProximityBitsV5 = 76.80;
/** Deprecated alias (the base is now v5, not v4). */
inline constexpr double kRCGkrFriProximityBitsV4 = kRCGkrFriProximityBitsV5;
/** Margin over the 64-bit target below which the composed bound is flagged
 *  INADEQUATE for consensus authority (audit gate; arbiter stays hard-disabled).
 *  At Q = 128 / Fp3 the margin is ≈ 12.8 bits ⇒ adequate (inadequate_margin
 *  false). */
inline constexpr double kRCGkrAdequateMarginBits = 2.0;
/** The ≥ 74-bit "restored-margin" acceptance bar of the full Q = 128 + Fp3
 *  margin restoration — REACHED by the shipped Q = 128 / Fp3 composed bound
 *  (≈ 76.8). (The intermediate Q = 128 / Fp2 state landed at ≈ 71.9, below
 *  this bar; the Fp2-challenge record is retained in the per-constant
 *  comments above.) */
inline constexpr double kRCGkrComposedTargetBits = 74.0;

struct RCGkrComposedBound {
    double construction_i_bits{0.0};   // Construction I evaluation opening (FS-side)
    double construction_ii_bits{0.0};  // composition
    double construction_iii_bits{0.0}; // lookup membership (dual-α)
    double construction_iv_bits{0.0};  // wiring (min of equality / dual permutation)
    double wiring_single_bits{0.0};    // excluded single-challenge path (dual mandate;
                                       // Fp3 124, historical Fp2 record 60 < 64)
    double fri_proximity_bits{0.0};    // parametric FRI term (76.80 at Q=128; the
                                       // binding floor under the Fp3 FS subtotal)
    double sha_bits{0.0};              // SHA256d computational
    double composed_bits{0.0};         // −log2(Σ 2^-term) over all of the above
    double margin_bits{0.0};           // composed_bits − 64
    bool clears_target{false};         // composed_bits ≥ 64
    bool fri_dominated{true};          // the FRI proximity term is the floor
    bool inadequate_margin{false};     // margin_bits < kRCGkrAdequateMarginBits
    bool any_term_below_target{false}; // any INCLUDED term < 64 (excludes wiring_single)
};

/** The full composed-bound breakdown, PARAMETRIC in the FRI proximity bits. */
[[nodiscard]] RCGkrComposedBound RCGkrComposedSeparation(double fri_proximity_bits);

/** The composed separation bound (−log2 ε_total). SHIPPED STATE: SOUND v5
 *  fold at Q = 128 with Fp3 challenges on the episode-v7 path — NON-VACUOUS
 *  and FRI-QUERY-dominated at ≈ 76.8 bits (ε_total ≤ 2^-76.8), clearing the
 *  2^-64 target by ≈ 12.8 bits and the ≥ 74-bit restored-margin bar
 *  (adequate: inadequate_margin false). Raising Q from 116 to 128 lifted the
 *  FRI floor (65.85 → 76.80); the Fp3 challenge cutover lifted the FS
 *  subtotal (72 → 135.5) above it, so the field-independent query term is now
 *  the binding floor. (Historical states: Q = 128 / Fp2 ≈ 71.9 FS-dominated;
 *  Q = 116 / Fp2 ≈ 65.8, an INADEQUATE < 2-bit margin.) The arbiter stays
 *  hard-disabled (`kRCGkrFormalSoundnessReady`) regardless — this bound is
 *  audit accounting, not a consensus switch. The parametric overload lets
 *  callers plug any FRI proximity term (e.g. the integer
 *  `Fri3BatchSoundnessBoundBits()` = 76). */
[[nodiscard]] double RCGkrComposedSeparationBits(double fri_proximity_bits);
[[nodiscard]] double RCGkrComposedSeparationBits();

enum class RCProdVerifyPath : uint8_t {
    ExactReplay = 0,
    WinnerGkr = 1,
    GkrFallbackExactReplay = 2,
    ShadowGkr = 3,
};

struct ExactReplayVerifyResult {
    bool ok{false};
    uint256 digest{};
    double verify_s{0};
    size_t rss_kib{0};
    size_t proof_bytes{0}; // always 0 — recompute is the check
    std::string note;
};

struct RCProdVerifyResult {
    bool ok{false};
    RCProdVerifyPath path{RCProdVerifyPath::ExactReplay};
    ExactReplayVerifyResult replay{};
    RCGkrTiming gkr{};
    std::string note;
};

[[nodiscard]] bool EnvRCWinnerGkrEnabled();
[[nodiscard]] bool EnvRCVerifyGkrEnabled();
/** Shadow mode: default ON unless BTX_RC_GKR_SHADOW=0. Never rejects consensus. */
[[nodiscard]] bool EnvRCGkrShadowEnabled();
/**
 * Arbiter cutover probe. Always false while !kRCGkrFormalSoundnessReady
 * (ignores BTX_RC_GKR_ARBITER). Even if someday true, does not raise height.
 */
[[nodiscard]] bool EnvRCGkrArbiterEnabled();

[[nodiscard]] DistSynthShape RCGkrShapeForEpisode(const RCEpisodeParams& params);
[[nodiscard]] DistSynthShape RCGkrShapeForCoupled(const RCCoupParams& params);

/**
 * DEPRECATED test-only: synth 32×32 proxy path. Prefer ProveWinnerEpisode.
 * Still emits succinct (FRI+LogUp) format — does not ship every tile.
 */
[[nodiscard]] RCGkrProveResult ProveWinnerSynth(const uint256& seed, const DistSynthShape& shape,
                                                const uint256& claimed_digest);

[[nodiscard]] RCGkrProveResult ProveWinnerFromSegments(
    const uint256& claimed_digest, const DistSynthShape& shape,
    const std::vector<std::vector<int64_t>>& segs, const uint256& extract_seed,
    const std::vector<int8_t>* A = nullptr, const std::vector<int8_t>* B = nullptr);

/**
 * Production API: ALL-PHASE arithmetization of the ACTUAL `params` (no
 * shrink-to-toy). Soft over_budget may still flag ExactReplay fallback.
 */
[[nodiscard]] RCGkrProveResult ProveWinnerEpisode(const CBlockHeader& header,
                                                 const RCEpisodeParams& params, int32_t height,
                                                 const uint256& resealed_digest);

/**
 * Coupled winner prove (Wave 3B): delegates to the sound coupled-R5 v7 prover
 * (matmul_v4_rc_gkr_coupled.h). timing.ok=true iff a real, self-verified
 * coupled proof was produced (the proof itself is v7-format; the v6 container
 * stays empty). Must never prove MakeToyRCEpisodeParams() / unrelated work:
 * fails closed unless resealed_digest equals the int64 coupled reference.
 */
[[nodiscard]] RCGkrProveResult ProveWinnerCoupled(const CBlockHeader& header, int32_t height,
                                                 const RCCoupParams& params,
                                                 const uint256& resealed_digest);

/** Expected ALL-PHASE layer count: rounds * (2 + 3*L_lyr). */
[[nodiscard]] size_t RCGkrExpectedLayerCount(const RCEpisodeParams& p);

/** Expected coupled layer count: barriers * (lobes * pages_per_lobe + 1 Extract). */
[[nodiscard]] size_t RCGkrExpectedCoupledLayerCount(const RCCoupParams& p,
                                                    bool full_bank_schedule = false);

/**
 * Succinct verify: sumcheck algebra + FRI openings + LogUp aggregate FS bind.
 * Does NOT re-run the episode / ExpandSynthOperands / Extract recompute.
 * G1–G5 OPEN/PARKED — see kRCGkrG1G5StatusStatement + completeness doc.
 */
[[nodiscard]] bool VerifyWinnerProof(const RCGkrProof& proof, RCGkrTiming* out_timing = nullptr);

/**
 * Public verify bound to seed+shape (DEPRECATED synth helper path). Prefer
 * VerifyWinnerProof for v3 succinct proofs.
 */
[[nodiscard]] bool VerifyWinnerProofPublic(const RCGkrProof& proof, const uint256& seed,
                                           const DistSynthShape& shape,
                                           RCGkrTiming* out_timing = nullptr);

[[nodiscard]] size_t SerializeRCGkrProof(const RCGkrProof& proof,
                                         std::vector<unsigned char>& out);
[[nodiscard]] std::optional<RCGkrProof> DeserializeRCGkrProof(
    const std::vector<unsigned char>& in);

[[nodiscard]] uint32_t RCGkrNextPow2(uint32_t n);
[[nodiscard]] Fp RCGkrMleEval1D(const std::vector<Fp>& evals_pow2, const std::vector<Fp>& r);
[[nodiscard]] Fp2 RCGkrMleEval1D2(const std::vector<Fp2>& evals_pow2, const std::vector<Fp2>& r);
/** Fp3 sibling (episode-v7 path / Fp3 wiring constraints). */
[[nodiscard]] Fp3 RCGkrMleEval1D3(const std::vector<Fp3>& evals_pow2, const std::vector<Fp3>& r);

/**
 * FALLBACK / DISPUTE verifier: ε=0 bounded exact STREAMED replay.
 * CONSENSUS arbiter while kRCGkrFormalSoundnessReady is false (arbiter hard-off).
 */
[[nodiscard]] ExactReplayVerifyResult VerifyBoundedExactReplay(
    const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
    const arith_uint256* target = nullptr);

/**
 * Dual-path helper. Shadow never fails consensus; arbiter OFF ⇒ ExactReplay
 * decides. Over-budget GKR invokes shrink-to-ExactReplay.
 */
[[nodiscard]] RCProdVerifyResult VerifyRCWinnerOrExactReplay(
    const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
    const arith_uint256* target = nullptr,
    const std::vector<unsigned char>* optional_gkr_proof = nullptr);

/**
 * Shadow hook for CheckMatMulProofOfWork_RC: never changes the bool result.
 * When prior_replay is non-null, reuse it instead of calling
 * VerifyBoundedExactReplay again (H2 memoization).
 */
void RCGkrShadowObserve(const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
                        const arith_uint256* target,
                        const std::vector<unsigned char>* optional_gkr_proof,
                        const ExactReplayVerifyResult* prior_replay = nullptr);

/** H1: bounded proof cache — max entries + TTL (LRU eviction on Put). */
inline constexpr size_t kRCGkrProofCacheMaxEntries = 64;
inline constexpr int64_t kRCGkrProofCacheTtlSeconds = 600;

void RCGkrProofCachePut(const uint256& block_hash, std::vector<unsigned char> proof_bytes);
[[nodiscard]] bool RCGkrProofCacheGet(const uint256& block_hash,
                                      std::vector<unsigned char>& out_proof_bytes);
void RCGkrProofCacheClear();
[[nodiscard]] size_t RCGkrProofCacheSizeForTest();

/** H2: ExactReplay call-count probe (incremented in VerifyBoundedExactReplay). */
[[nodiscard]] uint64_t ExactReplayInvocationCountForTest();
void ResetExactReplayInvocationCountForTest();

struct WinnerGkrSolveReport {
    uint256 digest{};
    uint64_t nonce{0};
    uint64_t nonces_tried{0};
    double mine_s{0};
    double reseal_s{0};
    double prove_s{0};
    double verify_s{0};
    size_t proof_bytes{0};
    size_t peak_rss_kib{0};
    bool ok{false};
    bool proved{false};
    bool hbm_parked{false};
    bool used_shrink_fallback{false};
    std::string note;
    RCGkrProof proof;
};

[[nodiscard]] WinnerGkrSolveReport SolveRCEpisodeProveWinner(
    CBlockHeader header, const RCEpisodeParams& params, int32_t height,
    const arith_uint256& target, uint64_t max_tries, bool do_prove = true);

[[nodiscard]] WinnerGkrSolveReport SolveCoupledProveWinner(
    CBlockHeader header, int32_t height, const RCCoupParams& params,
    const arith_uint256& target, uint64_t max_tries, bool do_prove = true);

[[nodiscard]] std::string RunWinnerGkrBakeoffSection(const uint256& synth_seed,
                                                     const DistSynthShape& shape);

/** Instrumented toy+medium measurement blob (JSON). Real-episode path. */
[[nodiscard]] std::string MeasureWinnerGkrToyMedium(const uint256& seed);

/** CSV-friendly curve helper for STATUS / selfqual hooks. */
[[nodiscard]] std::string MeasureWinnerGkrCurveCsv(const CBlockHeader& header);

/**
 * Independent malicious proof constructors (test / audit only).
 * These rebuild a full transcript from fabricated witnesses — NOT bit-flips of
 * an honest proof. Where a gap is OPEN, VerifyWinnerProof currently ACCEPTS.
 */
enum class RCGkrIndepMaliciousKind : uint32_t {
    /** G1: any a_at_r,b_at_r with a*b=final_eval (no PCS opening). */
    ArbitraryAbFactorization = 1,
    /** G1/G2: layer a_root/b_root/y_root unrelated to a_fri/b_fri/trace_fri. */
    UnrelatedLayerRoots = 2,
    /** G2: A/B/Y wires unrelated to episode PRF expansion / round seeds. */
    FabricatedTraceWires = 3,
    /** G3: identical fabricated witness/table keys (no Extract relation). */
    IdenticalFabricatedLookup = 4,
    /** G3/G4: fabricated Extract I/O; prover recomputes all prover-owned fields. */
    FabricatedExtractIO = 5,
    /** Coupled: lobe B matrix unrelated to bank page under bank_root. */
    UnrelatedBankPages = 6,
    /** Coupled: omit a scheduled page GEMM from the layer list. */
    OmittedPages = 7,
    /** Coupled: duplicate a scheduled page GEMM in the layer list. */
    DuplicatedPages = 8,
    /** Coupled: layer.m ≠ coup.rows_per_lobe (Wrong M). */
    WrongM = 9,
    /** Coupled: witness as if exchange/mix domain differed (scaffold gap). */
    WrongExchangeTranscript = 10,
    /** Replay a proof under a different proof.version. */
    CrossVersionReplay = 11,
};

[[nodiscard]] const char* RCGkrIndepMaliciousGapNote(RCGkrIndepMaliciousKind kind);

[[nodiscard]] RCGkrProveResult ProveIndepMaliciousEpisodeForTest(
    const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
    const uint256& claimed_digest, RCGkrIndepMaliciousKind kind);

[[nodiscard]] RCGkrProveResult ProveIndepMaliciousCoupledForTest(
    const CBlockHeader& header, int32_t height, const RCCoupParams& params,
    const uint256& claimed_digest, RCGkrIndepMaliciousKind kind);

/**
 * Test/audit-only INTERNALLY-CONSISTENT v7 forgery constructor. Runs the FULL
 * honest v7 prover machinery over a FABRICATED witness (per `kind`), producing
 * an RCGkrProofV7 that PASSES every trivial/algebraic gate of VerifyWinnerProofV7
 * (pow_bind, header/digest/sigma binding, digest_from_roots, round-seed chain, Λ
 * layout, column_not_grounded, batched FRI, per-layer sumcheck, final_eval,
 * eval-argument, FS-bound LogUp α's) and can therefore be rejected ONLY by the
 * deep in-circuit grounding AIRs (MxExpand / Extract-sampler / tile-tree). Use to
 * prove v7 defeats independent forgeries at the SECURITY MECHANISM, not at a
 * trivial consistency gate. For UnrelatedLayerRoots the returned proof re-seals
 * claimed_digest to the forged roots (bind header.matmul_digest to it before
 * verifying). UnrelatedBankPages is coupled-only (episode API has no bank pages).
 */
[[nodiscard]] RCGkrProveResultV7 ProveMaliciousEpisodeV7ForTest(
    const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
    const arith_uint256& target, const uint256& claimed_digest, RCGkrIndepMaliciousKind kind);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_GKR_H
