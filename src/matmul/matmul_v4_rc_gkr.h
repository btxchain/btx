// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_GKR_H
#define BTX_MATMUL_MATMUL_V4_RC_GKR_H

#include <arith_uint256.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_distributed.h>
#include <matmul/matmul_v4_rc_gkr_field.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// ENC_RC Stage E → Section 2 PRODUCTION — winner-only GKR/sumcheck + ExactReplay
// fallback. Beyond bake-off: serializable proof, dual-path verifier, soundness
// bound after PoW grinding, optional env hooks. Does NOT raise nMatMulRCHeight.
//
// Protocol shape (digest-bound synth proxy for full episode / coupled):
//   - GEMM: Thaler product sumcheck over k (linear GEMMs)
//   - All-to-all: segment-axis sumcheck over consensus K-segment partials
//   - LOOKUP: LogUp-style ExtractMXTileInt64 opening for EVERY Extract tile
//
// SOUNDNESS (computational, NOT ε=0):
//   Total error ≤ 2^{-64} AFTER PoW grinding under SHA256d FS (ROM) + Goldilocks
//   |F|=2^{64}-2^{32}+1, deg≤2 sumcheck, transcript binds matmul_digest.
//   Merkle q=8 sampling is a DoS PREFILTER ONLY — not part of this bound.
//
// Consensus today: ε=0 ExactReplay (CheckMatMulProofOfWork_RC). GKR is optional
// behind BTX_RC_VERIFY_GKR=1 (default OFF). Full STREAMED replay = DISPUTE /
// fallback when GKR disabled, missing, malformed, or over budget.
// HBM-scale GKR may be PARKED if medium prove already misses budget.

namespace matmul::v4::rc {

inline constexpr uint32_t kRCGkrProofVersion = 2;
inline constexpr char kRCGkrDomainTag[] = "BTX_RC_GKR_WINNER_V2";
/** Magic for optional out-of-band / cache carriage (not consensus body). */
inline constexpr uint32_t kRCGkrProofMagic = 0x524b4732u; // 'RK G2' LE-ish

inline constexpr const char* kRCGkrSoundnessBoundStatement =
    "Winner-only GKR/sumcheck: COMPUTATIONAL soundness error ≤ 2^{-64} AFTER "
    "accounting for PoW grinding attempts. Model: SHA256d Fiat–Shamir (domain-"
    "tagged ROM) with transcript binding of matmul_digest (PoW object) before "
    "challenges; Goldilocks |F|=2^{64}-2^{32}+1; sumcheck degree ≤ 2; per-round "
    "error O(deg/|F|). With R_tot rounds ≪ 2^{32} and PoW work dominating "
    "nonce/digest selection, residual forgery probability after grinding is "
    "≤ 2^{-64}. NOT ε=0. Merkle q=8 is DoS PREFILTER ONLY (not in this bound). "
    "Full STREAMED ExactReplay remains dispute/oracle until Stage-I cutover. "
    "nMatMulRCHeight=INT32_MAX.";

inline constexpr const char* kRCGkrSoundnessStatement = kRCGkrSoundnessBoundStatement;
inline constexpr const char* kRCGkrSoundnessNote = kRCGkrSoundnessBoundStatement;

inline constexpr const char* kRCGkrE5Decision =
    "DECIDED: winner-only GKR/sumcheck. Fraud-proof deferred. Shrink/"
    "ExactReplay is fallback if GKR verify cost fails Stage-I budget.";

inline constexpr const char* kRCGkrMerkleQ8PrefilterStatement =
    "kRCSpotCheckQueries=8 Merkle leaf sampling is a bandwidth DoS PREFILTER "
    "ONLY. It is NOT a soundness claim and MUST NOT be sole consensus validity "
    "(P2.1 f^q grinding). Production soundness is GKR bound ≤ 2^{-64} after "
    "PoW grinding, or ε=0 ExactReplay dispute/fallback.";

inline constexpr const char* kRCGkrHbmParkStatement =
    "If medium-shape prove already exceeds a small fraction of block-interval "
    "budget, HBM-scale winner GKR is PARKED; ship both verifiers (GKR + "
    "VerifyBoundedExactReplay) and keep ε=0 ExactReplay as consensus default.";

using gkr_field::Fp;

/** One sumcheck round: g(0), g(1), g(2) (deg-2 product; deg-1 uses eval2=0). */
struct RCGkrSumcheckRound {
    Fp eval0{0};
    Fp eval1{0};
    Fp eval2{0};
};

/** Extract tile opening (LogUp-shaped membership via ExtractMXTileInt64). */
struct RCGkrLookupOpening {
    uint32_t row{0};
    uint32_t block{0};
    std::vector<int64_t> raw64;
    std::vector<int8_t> out8;
    uint8_t scale{0};
    uint64_t multiplicity{1};
};

struct RCGkrProof {
    uint32_t version{kRCGkrProofVersion};
    uint256 claimed_digest{};
    DistSynthShape shape{};
    std::vector<int64_t> claimed_Y;
    std::vector<int8_t> claimed_extract;
    std::vector<RCGkrSumcheckRound> sumcheck;      // all-to-all / segment-axis
    std::vector<RCGkrSumcheckRound> gemm_sumcheck; // GEMM product over k
    Fp final_eval{0};
    Fp gemm_final_eval{0};
    Fp lookup_logup_sum{0};
    std::vector<RCGkrLookupOpening> lookups; // every Extract tile
    uint256 transcript_hash{};
    /** PoW-grinding resistance: FS absorbs this PoW-bind tag after digest. */
    uint256 pow_bind{};
};

struct RCGkrTiming {
    double prove_s{0};
    double verify_s{0};
    size_t proof_bytes{0};
    size_t peak_rss_kib{0};
    bool ok{false};
    bool over_budget{false};
    std::string note;
};

struct RCGkrProveResult {
    RCGkrProof proof;
    RCGkrTiming timing;
};

/** Soft prove budget for medium (fraction of ~10 min block); park signal. */
inline constexpr double kRCGkrMediumProveBudgetS = 2.0;

enum class RCProdVerifyPath : uint8_t {
    ExactReplay = 0,
    WinnerGkr = 1,
    GkrFallbackExactReplay = 2,
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

[[nodiscard]] DistSynthShape RCGkrShapeForEpisode(const RCEpisodeParams& params);
[[nodiscard]] DistSynthShape RCGkrShapeForCoupled(const RCCoupParams& params);

[[nodiscard]] RCGkrProveResult ProveWinnerFromSegments(
    const uint256& claimed_digest, const DistSynthShape& shape,
    const std::vector<std::vector<int64_t>>& segs, const uint256& extract_seed,
    const std::vector<int8_t>* A = nullptr, const std::vector<int8_t>* B = nullptr);

[[nodiscard]] RCGkrProveResult ProveWinnerSynth(const uint256& seed, const DistSynthShape& shape,
                                                const uint256& claimed_digest);

[[nodiscard]] RCGkrProveResult ProveWinnerEpisode(const CBlockHeader& header,
                                                 const RCEpisodeParams& params, int32_t height,
                                                 const uint256& resealed_digest);

[[nodiscard]] RCGkrProveResult ProveWinnerCoupled(const CBlockHeader& header, int32_t height,
                                                 const RCCoupParams& params,
                                                 const uint256& resealed_digest);

[[nodiscard]] bool VerifyWinnerProof(const RCGkrProof& proof, const DistSynthShape& shape,
                                     const std::vector<std::vector<int64_t>>& segs,
                                     const uint256& extract_seed,
                                     RCGkrTiming* out_timing = nullptr);

[[nodiscard]] bool VerifyWinnerProofPublic(const RCGkrProof& proof, const uint256& seed,
                                           const DistSynthShape& shape,
                                           RCGkrTiming* out_timing = nullptr);

/** Serialize proof bytes (block/cache carriage). Returns byte count. */
[[nodiscard]] size_t SerializeRCGkrProof(const RCGkrProof& proof,
                                         std::vector<unsigned char>& out);

/** Deserialize; returns nullopt on malformed / truncated / bad version. */
[[nodiscard]] std::optional<RCGkrProof> DeserializeRCGkrProof(
    const std::vector<unsigned char>& in);

[[nodiscard]] uint32_t RCGkrNextPow2(uint32_t n);
[[nodiscard]] Fp RCGkrMleEval1D(const std::vector<Fp>& evals_pow2, const std::vector<Fp>& r);

/**
 * FALLBACK / DISPUTE verifier: ε=0 bounded exact STREAMED replay via
 * RecomputeResidentCurriculumReference. Used when GKR disabled, missing,
 * malformed, over budget, or as ultimate oracle.
 */
[[nodiscard]] ExactReplayVerifyResult VerifyBoundedExactReplay(
    const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
    const arith_uint256* target = nullptr);

/**
 * Production dual-path: if BTX_RC_VERIFY_GKR=1 and optional_proof deserializes
 * and verifies, return WinnerGkr; else ExactReplay (and
 * GkrFallbackExactReplay when GKR was attempted and failed).
 * Consensus CheckMatMulProofOfWork_RC still requires ExactReplay unless the
 * env hook elects GKR-first with replay fallback (see pow.cpp).
 */
[[nodiscard]] RCProdVerifyResult VerifyRCWinnerOrExactReplay(
    const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
    const arith_uint256* target = nullptr,
    const std::vector<unsigned char>* optional_gkr_proof = nullptr);

/** Process-local optional proof cache (empty-body DIGEST_RECOMPUTE safe). */
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

/** Instrumented toy+medium measurement blob (JSON fragment). */
[[nodiscard]] std::string MeasureWinnerGkrToyMedium(const uint256& seed);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_GKR_H
