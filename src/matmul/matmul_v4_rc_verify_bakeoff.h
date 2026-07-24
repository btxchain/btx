// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_VERIFY_BAKEOFF_H
#define BTX_MATMUL_MATMUL_V4_RC_VERIFY_BAKEOFF_H

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_distributed.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

// ENC_RC Stage E — verification bake-off prototypes (TOY ONLY).
//
// E1: Full exact STREAMED replay remains the sole ε=0 consensus check.
// E2: 8-leaf Merkle sampling is a DoS PREFILTER ONLY — never O(1) verify.
// E3: Prototypes A/B/C/D on a toy trace (winner-only measurements).
// E6: GKR/STARK change soundness to computational; fraud proofs = fork.
//
// These APIs MUST NOT be called from CheckMatMulProofOfWork_RC / validation.

namespace matmul::v4::rc {

/** Wall + RSS measurement (Linux getrusage /proc; best-effort elsewhere). */
struct BakeoffTiming {
    double wall_s{0};
    double verify_s{0};
    size_t rss_kib{0};
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

/** E1 statement — kept in comments + this constant for doc generators. */
inline constexpr const char* kBakeoffE1Statement =
    "Full exact STREAMED replay (RecomputeResidentCurriculumReference / "
    "CheckMatMulProofOfWork_RC) remains the sole ε=0 consensus validity check. "
    "No bake-off prototype replaces it on the validation path.";

/** E2 statement. */
inline constexpr const char* kBakeoffE2Statement =
    "kRCSpotCheckQueries=8 Merkle leaf sampling is a bandwidth DoS PREFILTER "
    "ONLY. It is NOT an O(1) consensus verifier and MUST NOT be claimed as such "
    "(see P2.1: f^q grinding).";

// --- E3-A: exact bounded-memory replay baseline --------------------------------

struct BakeoffAResult {
    uint256 digest{};
    BakeoffTiming timing;
};

/** Wrap existing RecomputeResidentCurriculumReference (toy params). */
[[nodiscard]] BakeoffAResult BakeoffA_ExactReplay(const CBlockHeader& header,
                                                  const RCEpisodeParams& params,
                                                  int32_t height = 0);

// --- E3-B: toy GKR/sumcheck-shaped + Extract table-lookup (educational) --------
// NOT production crypto. Fiat–Shamir challenges over SHA256 only.

struct ToyGkrProof {
    /** Claimed sum of segment partials (m×n int64), then Extracted int8. */
    std::vector<int64_t> claimed_sum;
    std::vector<int8_t> claimed_extract;
    /** Sumcheck-shaped: one FS challenge per log2(#segs) round + evaluations. */
    std::vector<uint256> fs_challenges;
    std::vector<int64_t> round_evals; // educational linear combinations
    /** Extract table-lookup check: MixBits/Extract recompute match flags. */
    bool extract_in_table{false};
    uint256 transcript_commit{};
};

struct BakeoffBResult {
    ToyGkrProof proof;
    BakeoffTiming prove;
    BakeoffTiming verify;
};

/**
 * Prove: sum of synthetic segment partials + Extract output matches MixBits
 * table (recompute ExtractMX and compare). Educational GKR/sumcheck shape over
 * the segment axis only.
 */
[[nodiscard]] BakeoffBResult BakeoffB_ToyGkrSumcheck(const uint256& seed,
                                                     const DistSynthShape& shape);

// --- E3-C: STARK/AIR+FRI stub (interface only) ---------------------------------

struct StarkAirFriSketch {
    bool implemented{false};
    std::string reason;
    size_t estimated_proof_bytes_toy{0};
};

[[nodiscard]] StarkAirFriSketch BakeoffC_StarkStub();

// --- E3-D: structural spot-check + compact fraud-proof sketch ------------------
// DO NOT bolt onto the validation path.

struct FraudProofSketch {
    uint32_t challenged_segment{0};
    std::vector<int64_t> claimed_partial;
    std::vector<int64_t> recomputed_partial;
    bool mismatch{false};
    uint256 claimed_digest{};
    uint256 honest_digest{};
    std::string fork_requirements; // challenge window, DA, bonds
};

struct BakeoffDResult {
    FraudProofSketch sketch;
    BakeoffTiming timing;
    /** Spot-check prefilter result (DoS only — see E2). */
    bool spot_check_prefilter_ok{false};
};

[[nodiscard]] BakeoffDResult BakeoffD_FraudProofSketch(const uint256& seed,
                                                       const DistSynthShape& shape,
                                                       uint32_t challenged_segment,
                                                       bool inject_fault);

/** Run A–D and return a human/JSON-friendly report string. */
[[nodiscard]] std::string RunBakeoffReport(const CBlockHeader& header,
                                           const RCEpisodeParams& toy_params,
                                           const uint256& synth_seed);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_VERIFY_BAKEOFF_H
