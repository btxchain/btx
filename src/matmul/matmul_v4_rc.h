// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_H
#define BTX_MATMUL_MATMUL_V4_RC_H

#include <matmul/matmul_v4_rc_extract.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

// ENC_RC / Resident Curriculum — 3-phase cognitive-workout episode.
// Normative: doc/btx-matmul-v4.4-resident-curriculum-unified-proposal-2026-07-20.md §R
//
// Consensus ground truth is the int64 CPU reference
// (RecomputeResidentCurriculumReference). Accelerated paths must prove
// byte-identity before mining use; only the CPU reference may pronounce INVALID.
//
// Activation: Consensus::Params::nMatMulRCHeight (default INT32_MAX).

namespace matmul::v4::rc {

/** Consensus structural parameters (R.0) — fixed by height, identical per nonce. */
inline constexpr uint32_t kRCRounds = 4;
inline constexpr uint32_t kRCHeadDim = 128;
inline constexpr uint32_t kRCQueryRows = 512;
inline constexpr uint32_t kRCContextLen = 786'432; // 0.75 Mi
inline constexpr uint32_t kRCLayers = 16;
inline constexpr uint32_t kRCModelDim = 4096;
inline constexpr uint32_t kRCBatchSeq = 16'384;
inline constexpr uint32_t kRCTileLeafBytes = 1024; // 32×32 int8

static_assert(kRCHeadDim % 32 == 0, "kRCHeadDim must be divisible by 32");
static_assert(kRCQueryRows % 32 == 0, "kRCQueryRows must be divisible by 32");
static_assert(kRCContextLen % 32 == 0, "kRCContextLen must be divisible by 32");
static_assert(kRCModelDim % 32 == 0, "kRCModelDim must be divisible by 32");
static_assert(kRCBatchSeq % 32 == 0, "kRCBatchSeq must be divisible by 32");
static_assert(kRCMxBlockLen == 32, "MX block length is fixed at 32");
// Episode int64 accumulator invariant (R.1.4): 2304·n_ctx < 2^62.
static_assert(static_cast<uint64_t>(kRCContextLen) * 2304ull < (uint64_t{1} << 62),
              "2304·n_ctx must fit in signed int64 headroom (< 2^62)");

/** Domain-separation tags (frozen byte strings — R.4). */
inline constexpr char kRCRoundTag[] = "BTX_RC_ROUND_V1";
inline constexpr char kRCEpisodeTag[] = "BTX_RC_EPISODE_V1";
inline constexpr char kRCPadTag[] = "BTX_RC_PAD";
inline constexpr uint8_t kRCLeafTag = 0x00;
inline constexpr uint8_t kRCNodeTag = 0x01;
inline constexpr uint8_t kRCPadLeafTag = 0x02;

/** Per-episode shape (consensus constants or toy dims for tests / harness). */
struct RCEpisodeParams {
    uint32_t rounds{kRCRounds};
    uint32_t d_head{kRCHeadDim};
    uint32_t n_q{kRCQueryRows};
    uint32_t n_ctx{kRCContextLen};
    uint32_t L_lyr{kRCLayers};
    uint32_t d_model{kRCModelDim};
    uint32_t b_seq{kRCBatchSeq};
    uint32_t T_leaf{kRCTileLeafBytes};
};

/** Optional execution knobs that MUST NOT change digests (R.2.2 / R.3.3). */
struct RCEpisodeOptions {
    /** Phase-1 n_ctx tile length. 0 ⇒ whole context. Any positive ΔT that
     *  partitions [0,n_ctx) yields identical Z (tile-size invariance). */
    uint32_t phase1_tile_delta{0};
    enum class Checkpoint : uint8_t {
        StoreAll = 0,     // reference default
        StoreEvery4 = 1,  // recompute missing activations
        StoreOnlyX0 = 2,  // recompute all forward from X[0]
    };
    Checkpoint checkpoint{Checkpoint::StoreAll};
};

struct RCRoundTranscript {
    uint256 round_root{};
};

[[nodiscard]] bool ValidateRCEpisodeParams(const RCEpisodeParams& p);

[[nodiscard]] RCEpisodeParams DefaultConsensusRCEpisodeParams();
/** Tiny dims for unit tests — every matrix dim divisible by 32 (H13). */
[[nodiscard]] RCEpisodeParams MakeToyRCEpisodeParams();

/** Sole consensus ground truth (R.5.1). Pure int64 integer; MUST NOT dispatch
 *  to any accelerated/FP backend. Returns the 32-byte episode digest. */
[[nodiscard]] uint256 RecomputeResidentCurriculumReference(
    const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
    const RCEpisodeOptions& options = {},
    std::vector<RCRoundTranscript>* out_rounds = nullptr);

/** Miner entry: same digest as the CPU reference (reseal path). */
[[nodiscard]] uint256 MineRCEpisode(const CBlockHeader& header, const RCEpisodeParams& params,
                                    int32_t height,
                                    std::vector<RCRoundTranscript>* out_rounds = nullptr);

/** Spot-check verifier: recompute challenged Merkle leaves' stages.
 *  Accept-fast only — a REJECT requires full CPU recompute (R1). */
[[nodiscard]] bool VerifyRCTranscriptSpotCheck(
    const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
    const uint256& claimed_digest, const std::vector<uint32_t>& challenged_leaves);

/** Test/harness helpers (not consensus entry points). */
[[nodiscard]] std::vector<int8_t> ExpandMxDequantInt8(const uint256& seed, uint32_t rows,
                                                      uint32_t cols);
[[nodiscard]] uint256 BuildTileTreeRoot(const std::vector<int8_t>& stream, uint32_t t_leaf);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_H
