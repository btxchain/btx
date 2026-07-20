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
#include <matmul/matmul_v4_rc_gkr_field.h>
#include <matmul/matmul_v4_rc_gkr_field_ext.h>
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
//   This tip is a CODE-COMPLETE SCAFFOLD (Fp2 + REAL FRI + ALL-PHASE real-episode
//   arithmetization + shadow wiring). It is NOT production-complete / NOT
//   silicon-qualified. Soft over_budget may recommend ExactReplay (M4 shipping)
//   but MUST NOT replace the episode with toy-slice arithmetization.
//
// Consensus today: ε=0 ExactReplay (CheckMatMulProofOfWork_RC) is the arbiter.
// Shadow: BTX_RC_GKR_SHADOW=1 (default) generate+verify, log mismatches, never
// reject. Arbiter cutover BTX_RC_GKR_ARBITER=1 is OFF by default and does NOT
// raise height.

namespace matmul::v4::rc {

inline constexpr uint32_t kRCGkrProofVersion = 6;
inline constexpr char kRCGkrDomainTag[] = "BTX_RC_GKR_WINNER_V6";
/** Magic for optional out-of-band / cache carriage (not consensus body). */
inline constexpr uint32_t kRCGkrProofMagic = 0x524b4736u; // 'RKG6'

inline constexpr const char* kRCGkrRealityGuardrail =
    "REJECT HBM/production-complete GKR claims: succinct scaffold uses Fp2+REAL "
    "FRI and ALL-PHASE real-episode arithmetization (QKt/SV/Fwd/Bwd/Wgrad × "
    "rounds; no shrink-to-toy), but is NOT production-complete — require "
    "consensus-dim prove within budget + succinct/block-sized + no-rerun "
    "verify + formal <=2^{-64}-after-grinding bound (see soundness note). "
    "Soft over_budget → VerifyBoundedExactReplay is shrink-to-replayable for "
    "shipping (M4), not shrink-to-toy arithmetization. "
    "NOT production-complete. nMatMulRCHeight=INT32_MAX.";

inline constexpr const char* kRCGkrSoundnessBoundStatement =
    "Winner-only GKR/sumcheck+FRI SCAFFOLD (COMPUTATIONAL aspirational target): "
    "formal <=2^{-64} AFTER PoW grinding is a Stage-I REQUIREMENT. Challenges "
    "live in Goldilocks Fp2 (|F|~2^128); single Goldilocks is insufficient. "
    "M6/Fable FRI: unique-decoding Q=116, ρ=1/16, g=40, Fp2 → "
    "FriSoundnessBoundBits()=65. Fp3 only for g>=64 (unbuilt). "
    "DEEP/OOD exact-eval binding CLOSED (FRI v3). "
    "G3 Haböck LogUp + virtual Extract table (proof v6). "
    "M2: ALL-PHASE layers + round_seeds bound to sigma/round_roots. "
    "See doc/btx-matmul-v4.5-rc-succinct-proof-soundness-2026-07-20.md and "
    "kRCGkrRealityGuardrail. Merkle q=8 is DoS PREFILTER ONLY. "
    "Full STREAMED ExactReplay remains dispute/oracle until Stage-I cutover. "
    "nMatMulRCHeight=INT32_MAX.";

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

/** Coupled path: barrier all-to-all product layers are not separately
 *  arithmetized; ProveWinnerCoupled reuses ALL-PHASE episode layers (same kinds
 *  as ProveWinnerEpisode) without shrink-to-toy. ExactReplay covers coup mix. */
inline constexpr const char* kRCGkrCoupledArithStatement =
    "ProveWinnerCoupled: ALL-PHASE episode-layer stand-in (no shrink-to-toy); "
    "coupled barrier all-to-all mix remains ExactReplay-covered until dedicated "
    "coup product layers land.";

inline constexpr const char* kRCGkrShadowStatement =
    "BTX_RC_GKR_SHADOW=1 (default): generate+verify winner proof in shadow; "
    "mismatch LogWarning; NEVER rejects CheckMatMulProofOfWork_RC. "
    "BTX_RC_GKR_ARBITER=1 cutover is OFF by default and does NOT raise height; "
    "when OFF, ExactReplay decides.";

using gkr_field::Fp;
using gkr_field::Fp2;

/** Soft budgets for the Section-2 scaffold (CPU toy/medium). Not silicon. */
inline constexpr double kRCGkrMediumProveBudgetS = 2.0;
inline constexpr double kRCGkrVerifyBudgetS = 0.5;
inline constexpr size_t kRCGkrProofBytesBudget = 3 * 1024 * 1024; // 3 MiB soft (DEEP+A/B FRI)

/** One sumcheck round over Fp2: g(0), g(1), g(2) (deg-2 product). */
struct RCGkrSumcheckRound {
    Fp2 eval0{};
    Fp2 eval1{};
    Fp2 eval2{};
};

/** Layer kind in the ALL-PHASE real-episode arithmetization. */
enum class RCGkrLayerKind : uint32_t {
    GemmPhase1QKt = 1, // Q·Kᵀ product layer
    GemmPhase1SV = 2,  // S·V product layer
    GemmPhase2Fwd = 3, // forward residual GEMM
    GemmPhase2Bwd = 4, // backward GEMM
    GemmPhase2Wgrad = 5,
    SynthGemmDeprecated = 100, // DEPRECATED synth proxy only
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
     * Round seeds matching RunEpisode: seed[0]=Sha256TaggedU32(ROUND,sigma,0);
     * seed[r]=Sha256TaggedU32(ROUND, round_roots[r-1], r).
     */
    std::vector<uint256> round_seeds;
    /** Round merkle roots (tile-tree); digest = SHA256d(EPISODE ‖ roots…). */
    std::vector<uint256> round_roots;
    /** DeriveSigma(header) at prove time — verify re-derives seed[0] from this. */
    uint256 episode_sigma{};
    std::vector<RCGkrLayerClaim> layers;
    /**
     * G3 Haböck LogUp (ePrint 2022/1530):
     *   witness keys w_i = Hash(meta, in, out)
     *   table keys   t_i = Hash(meta, in, Extract(in))  // virtual Extract table
     *   Σ 1/(α−w_i) = Σ 1/(α−t_i)  (here enforced by w≡t + inverse column)
     * lookup_logup_sum = Σ inv_i with inv_i = 1/(α−t_i), proven via I(1) DEEP + R≡0.
     */
    Fp2 lookup_logup_sum{};
    Fp2 lookup_table_sum{}; // must equal lookup_logup_sum
    Fp2 logup_alpha{};
    /** Witness LogUp keys FRI. */
    FriProof lookup_fri{};
    /** Virtual Extract-table keys FRI (must match lookup_fri root/DEEP). */
    FriProof table_fri{};
    /** inv_i = 1/(α − t_i); DEEP at z=1 binds sum. */
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
/** Arbiter cutover: OFF by default. When ON still does not raise height. */
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
 * Coupled winner prove: reuses ALL-PHASE episode layers (see
 * kRCGkrCoupledArithStatement); does not shrink coup work to a toy slice.
 */
[[nodiscard]] RCGkrProveResult ProveWinnerCoupled(const CBlockHeader& header, int32_t height,
                                                 const RCCoupParams& params,
                                                 const uint256& resealed_digest);

/** Expected ALL-PHASE layer count: rounds * (2 + 3*L_lyr). */
[[nodiscard]] size_t RCGkrExpectedLayerCount(const RCEpisodeParams& p);

/**
 * Succinct verify: sumcheck algebra + FRI openings + LogUp aggregate FS bind.
 * Does NOT re-run the episode / ExpandSynthOperands / Extract recompute.
 * M7 completeness checks: layer dims, sumcheck round counts, FRI present.
 * OPEN gaps (A/B PCS, claim↔trace MLE, Extract table): see
 * doc/btx-matmul-v4.5-rc-arithmetization-completeness-2026-07-20.md.
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

/**
 * FALLBACK / DISPUTE verifier: ε=0 bounded exact STREAMED replay.
 * CONSENSUS arbiter while BTX_RC_GKR_ARBITER is OFF.
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

/** Shadow hook for CheckMatMulProofOfWork_RC: never changes the bool result. */
void RCGkrShadowObserve(const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
                        const arith_uint256* target,
                        const std::vector<unsigned char>* optional_gkr_proof);

void RCGkrProofCachePut(const uint256& block_hash, std::vector<unsigned char> proof_bytes);
[[nodiscard]] bool RCGkrProofCacheGet(const uint256& block_hash,
                                      std::vector<unsigned char>& out_proof_bytes);
void RCGkrProofCacheClear();

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

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_GKR_H
