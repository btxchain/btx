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

// ENC_RC Stage E — winner-only GKR/sumcheck scaffold + ExactReplay fallback.
// Does NOT raise nMatMulRCHeight.
//
// GKR REALITY GUARDRAIL (Amendment v2 — enforce always):
//   The CURRENT winner proof proves a SYNTHETIC 32×32 GEMM bound to the digest,
//   is NON-SUCCINCT (grows with state), has the verifier RE-RUN the work, and a
//   SINGLE Goldilocks field CANNOT deliver ≤2^{-64} after PoW grinding alone.
//   REJECT any "HBM proof production-complete" claim until ALL hold:
//     (1) proves the ACTUAL episode (not a synth proxy),
//     (2) is succinct / block-sized,
//     (3) verifies WITHOUT re-running the work,
//     (4) carries a formal ≤2^{-64}-after-grinding bound.
//   Expect shrink-to-bounded-replay (VerifyBoundedExactReplay) to fire otherwise.
//
// Consensus today: ε=0 ExactReplay (CheckMatMulProofOfWork_RC). GKR is optional
// behind BTX_RC_VERIFY_GKR=1 (default OFF).

namespace matmul::v4::rc {

inline constexpr uint32_t kRCGkrProofVersion = 2;
inline constexpr char kRCGkrDomainTag[] = "BTX_RC_GKR_WINNER_V2";
/** Magic for optional out-of-band / cache carriage (not consensus body). */
inline constexpr uint32_t kRCGkrProofMagic = 0x524b4732u; // 'RK G2' LE-ish

inline constexpr const char* kRCGkrRealityGuardrail =
    "REJECT HBM/production-complete GKR claims: current winner proof is a "
    "synthetic 32x32 GEMM digest-bound proxy, non-succinct, verifier re-runs "
    "work, and single Goldilocks cannot hit <=2^{-64} after grinding. Require "
    "actual-episode + succinct/block-sized + no-rerun verify + formal "
    "<=2^{-64}-after-grinding bound. Otherwise shrink to VerifyBoundedExactReplay. "
    "NOT production-complete. nMatMulRCHeight=INT32_MAX.";

inline constexpr const char* kRCGkrSoundnessBoundStatement =
    "Winner-only GKR/sumcheck SCAFFOLD (COMPUTATIONAL aspirational target): "
    "formal <=2^{-64} AFTER PoW grinding is a Stage-I REQUIREMENT, NOT a claim "
    "about the current synthetic proof. Current artifact: synth 32x32, "
    "non-succinct, verify re-runs work; single Goldilocks alone is insufficient. "
    "See kRCGkrRealityGuardrail. Merkle q=8 is DoS PREFILTER ONLY. "
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
    "If medium-shape prove already exceeds a small fraction of block-interval "
    "budget, PARK HBM-scale GKR; ship both verifiers (GKR scaffold + "
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
