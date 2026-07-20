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
#include <string>
#include <vector>

// ENC_RC Stage E DIRECTION LOCK — winner-only GKR/sumcheck (production path).
//
// Owner direction: winner-only GKR/sumcheck is THE Stage E verification path
// (not fraud-proof, not shrink-only). BakeoffB_ToyGkrSumcheck remains the
// educational stub; this module is the structured protocol.
//
// SOUNDNESS HONESTY (computational, NOT ε=0):
//   - Fiat–Shamir over SHA256d (domain-tagged) in the random-oracle model.
//   - Sumcheck soundness ~ O(deg / |F|) per round (Goldilocks |F|≈2^64).
//   - Extract lookup: table-oracle openings + LogUp-style multiplicity field
//     check (computational under FS); ExtractMXTileInt64 is the table oracle.
//   - Full exact STREAMED replay remains the dispute/oracle until Stage I
//     cutover. This proof MUST NOT be wired into CheckMatMulProofOfWork_RC
//     without that cutover. nMatMulRCHeight remains INT32_MAX.
//
// Prove ONLY on winning episodes (digest ≤ target). Losers pay zero prove cost.

namespace matmul::v4::rc {

inline constexpr uint32_t kRCGkrProofVersion = 1;
inline constexpr char kRCGkrDomainTag[] = "BTX_RC_GKR_WINNER_V1";

inline constexpr const char* kRCGkrSoundnessStatement =
    "Winner-only GKR/sumcheck provides COMPUTATIONAL soundness under SHA256d "
    "Fiat–Shamir + Goldilocks field bounds (deg/|F| per sumcheck round; LogUp "
    "FS binding for Extract). NOT ε=0. Full STREAMED replay remains available "
    "as dispute/oracle until Stage I cutover. nMatMulRCHeight=INT32_MAX.";

inline constexpr const char* kRCGkrSoundnessNote = kRCGkrSoundnessStatement;

inline constexpr const char* kRCGkrE5Decision =
    "DECIDED: winner-only GKR/sumcheck. Fraud-proof deferred. Shrink is "
    "fallback if GKR verify cost fails Stage-I budget.";

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
    std::vector<RCGkrSumcheckRound> sumcheck;      // segment-axis
    std::vector<RCGkrSumcheckRound> gemm_sumcheck; // Thaler product over k
    Fp final_eval{0};
    Fp gemm_final_eval{0};
    Fp lookup_logup_sum{0};
    std::vector<RCGkrLookupOpening> lookups;
    uint256 transcript_hash{};
};

struct RCGkrTiming {
    double prove_s{0};
    double verify_s{0};
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

struct RCGkrProveResult {
    RCGkrProof proof;
    RCGkrTiming timing;
};

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

[[nodiscard]] size_t SerializeRCGkrProof(const RCGkrProof& proof,
                                         std::vector<unsigned char>& out);

[[nodiscard]] uint32_t RCGkrNextPow2(uint32_t n);
[[nodiscard]] Fp RCGkrMleEval1D(const std::vector<Fp>& evals_pow2, const std::vector<Fp>& r);

struct WinnerGkrSolveReport {
    uint256 digest{};
    uint64_t nonce{0};
    uint64_t nonces_tried{0};
    double mine_s{0};
    double reseal_s{0};
    double prove_s{0};
    double verify_s{0};
    size_t proof_bytes{0};
    bool ok{false};
    bool proved{false};
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

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_GKR_H
