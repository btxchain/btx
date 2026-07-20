// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_H
#define BTX_MATMUL_MATMUL_V4_RC_H

#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

namespace Consensus {
struct Params;
}

// ENC_RC / Resident Curriculum — 3-phase cognitive-workout episode.
// Normative: doc/btx-matmul-v4.4-resident-curriculum-unified-proposal-2026-07-20.md §R
//
// Consensus ground truth is the int64 CPU reference
// (RecomputeResidentCurriculumReference with an empty ExactGemmBackend).
// Accelerated paths may inject ExactGemmBackend for <2^24 s8xs8 stages
// (forward / backward); a qualified device path REPLACES CPU on the hot path
// (P0.3). CPU is fallback when the device is absent/declines, or when
// BTX_RC_EXACT_GEMM_COMPARE=1 dispute mode detects a mismatch.
// Phase-1 Z=S·V stays int64-streamed in the reference (bound ≫ 2^24).
// Phase-2 wgrad G·Xᵀ uses int64 as oracle; an optional chunked ExactGemm
// path (TestHelperGemmGXtViaChunkedExact) must match byte-for-byte.
//
// REJECT / spot-check MUST use the CPU reference only (never accelerated).
//
// Activation: Consensus::Params::nMatMulRCHeight (default INT32_MAX).

namespace matmul::v4::rc {

/**
 * Consensus structural parameters (R.0) — epoch-0 / Class B frozen bases.
 * Equal to EpisodeParamsFromScale({kRCW0Res, kRCW0Cap}) in matmul_v4_rc_scale.h.
 * Class A dials (W_res/W_cap) may grow with height; these literals stay the
 * epoch-0 shape and the frozen ratios (d_head, L_lyr, d_model, rounds, T_leaf).
 */
inline constexpr uint32_t kRCRounds = 4;
inline constexpr uint32_t kRCHeadDim = 128;
inline constexpr uint32_t kRCQueryRows = 512;       // == 4 * kRCHeadDim
inline constexpr uint32_t kRCContextLen = 786'432; // 0.75 Mi; == W_res/(2*d_head) at epoch 0
inline constexpr uint32_t kRCLayers = 16;
inline constexpr uint32_t kRCModelDim = 4096;
inline constexpr uint32_t kRCBatchSeq = 16'384; // == W_cap/(2*d_model*L_lyr) at epoch 0
inline constexpr uint32_t kRCTileLeafBytes = 1024; // 32×32 int8 (Class C)

/** Max K-chunk for wgrad ExactGemm panels: 2304·K < 2^24 (FP32-mantissa ceiling). */
inline constexpr uint32_t kRCWgradExactChunk = 4096;
static_assert(static_cast<uint64_t>(kRCWgradExactChunk) * 2304ull < (uint64_t{1} << 24),
              "wgrad ExactGemm chunk must stay under the 2^24 FP32-exact ceiling");

/** Fixed consensus K-segment length for Phase-1 Z=S·V and Phase-2 wgrad G·Xᵀ
 *  (§R.7 / §3). Never scales with epoch dials. Each segment's exact int64
 *  partial is committed as additional tile-tree leaves (LE int64 row-major)
 *  before the final Extracted int8 tensor. ExtractMX still fires once on the
 *  sum of partials (H1). Per-segment bound 2304·kRCSegLen ≈ 2^26.2 still
 *  needs int64 (or kRCWgradExactChunk sub-chunking inside a segment for
 *  FP32 backends). Class C eternal — also exported for scale schedule. */
inline constexpr uint32_t kRCSegLen = 32768;
static_assert(static_cast<uint64_t>(kRCSegLen) * 2304ull < (uint64_t{1} << 62),
              "2304·kRCSegLen must fit in signed int64 headroom (< 2^62)");
static_assert((kRCSegLen % 32) == 0, "kRCSegLen must be divisible by 32 (MX align)");


/** PARKED (§R.7 STOP-AND-STABILIZE): segment-partial leaves stay OFF so the
 *  committed stream matches pre-segment layout. Do not enable until the
 *  validation model (P2.1) is decided. */
inline constexpr bool kRCSegmentLeavesEnabled = false;

/** PARKED (§R.7 STOP-AND-STABILIZE): growth schedule stays OFF — always epoch-0
 *  dials. Keep reparam/ratios; do not step growth or brake. */
inline constexpr bool kRCGrowthScheduleEnabled = false;

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
inline constexpr char kRCFsTag[] = "BTX_RC_FS_V1";
inline constexpr uint8_t kRCLeafTag = 0x00;
inline constexpr uint8_t kRCNodeTag = 0x01;
inline constexpr uint8_t kRCPadLeafTag = 0x02;
/** Fiat–Shamir spot-check query count (optimistic accept-fast pre-filter). */
inline constexpr uint32_t kRCSpotCheckQueries = 8;

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
    /** Phase-1 n_ctx tile length. 0 ⇒ whole context. Any positive ΔT is
     *  allowed (§R.2.2): incomplete MX 32-blocks are buffered across tile
     *  windows so Extract boundaries stay on bj = ⌊t/32⌋. */
    uint32_t phase1_tile_delta{0};
    enum class Checkpoint : uint8_t {
        StoreAll = 0,     // reference default
        StoreEvery4 = 1,  // recompute missing activations
        StoreOnlyX0 = 2,  // recompute all forward from X[0]
    };
    Checkpoint checkpoint{Checkpoint::StoreAll};
};

/** Optional wall-clock timing for harness / measurement (not consensus). */
struct RCEpisodeTiming {
    double phase1_s{0};
    double phase2_s{0};
    double phase3_s{0};
    double total_s{0};
};

struct RCRoundTranscript {
    uint256 round_root{};
    /** Round byte stream (R.4.1 + §3 segment leaves); filled when collected via
     *  out_rounds. Layout: [Z_seg0..Z_segN LE int64] ‖ Z_int8 ‖ for each layer
     *  (X[l+1] ‖ G[l] ‖ [D_seg0..D_segM LE int64] ‖ D_int8). */
    std::vector<int8_t> stream{};
};

/** Merkle opening: siblings from leaf toward root (index parity selects side). */
struct RCMerkleProof {
    std::vector<uint256> siblings{};
};

[[nodiscard]] bool ValidateRCEpisodeParams(const RCEpisodeParams& p);

/** Epoch-0 consensus dims: EpisodeParamsFromScale({kRCW0Res, kRCW0Cap}). */
[[nodiscard]] RCEpisodeParams DefaultConsensusRCEpisodeParams();
/** Tiny dims for unit tests — every matrix dim divisible by 32 (H13). */
[[nodiscard]] RCEpisodeParams MakeToyRCEpisodeParams();
/** Medium dims for self-qual: wgrad contraction exceeds 2^24 (b_seq ≥ 8192). */
[[nodiscard]] RCEpisodeParams MakeMediumRCEpisodeParams();
/** Segmentation exercise: n_ctx = kRCSegLen+32 so Phase-1 spans two segments;
 *  Phase-2 stays tiny (b_seq < kRCSegLen → one D segment). */
[[nodiscard]] RCEpisodeParams MakeSegTestRCEpisodeParams();
/** Consensus checker/miner dims: toy when Params::fMatMulRCUseToyDims (regtest
 *  only), else ConsensusRCEpisodeParamsForHeight(height, p) — see
 *  matmul_v4_rc_scale.h for the height-selected schedule API. */
[[nodiscard]] RCEpisodeParams ResolveRCEpisodeParams(const Consensus::Params& p, int32_t height);

/** Sole consensus ground truth (R.5.1). Pure int64 integer by default.
 *  Optional `gemm` may accelerate Phase-2 s8xs8 stages (bound < 2^24) when a
 *  device backend is injected (P0.3: device replaces CPU; CPU is fallback /
 *  dispute via BTX_RC_EXACT_GEMM_COMPARE=1).
 *  Consensus REJECT / spot-check MUST pass an empty backend. */
[[nodiscard]] uint256 RecomputeResidentCurriculumReference(
    const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
    const RCEpisodeOptions& options = {},
    std::vector<RCRoundTranscript>* out_rounds = nullptr,
    RCEpisodeTiming* out_timing = nullptr,
    const matmul::v4::lt::ExactGemmBackend& gemm = {});

/** Miner entry: same digest as the CPU reference. May inject ExactGemmBackend
 *  after RC self-qualification (fail-closed → empty backend = CPU). */
[[nodiscard]] uint256 MineRCEpisode(const CBlockHeader& header, const RCEpisodeParams& params,
                                    int32_t height,
                                    std::vector<RCRoundTranscript>* out_rounds = nullptr,
                                    const matmul::v4::lt::ExactGemmBackend& gemm = {});

/** Spot-check verifier (R.5.3): recompute episode streams, open challenged
 *  Merkle leaves against round_roots. If challenged_leaves is empty, derive
 *  q=kRCSpotCheckQueries flat leaf indices via Fiat–Shamir
 *  SHA256d("BTX_RC_FS_V1"‖sigma‖claimed_digest‖le32(q)).
 *
 *  Returns false on any leaf failure (accept-fast fail). Returns true only as
 *  an optimistic accept — consensus INVALID still requires the full int64
 *  recompute in CheckMatMulProofOfWork_RC (R1). NEVER dispatches accelerators.
 *
 *  stream_override: optional per-round streams for leaf bytes (tests / openings);
 *  paths are checked against the recomputed round_roots. */
[[nodiscard]] bool VerifyRCTranscriptSpotCheck(
    const CBlockHeader& header, const RCEpisodeParams& params, int32_t height,
    const uint256& claimed_digest, const std::vector<uint32_t>& challenged_leaves,
    const std::vector<std::vector<int8_t>>* stream_override = nullptr);

/** Test/harness helpers (not consensus entry points). */
[[nodiscard]] std::vector<int8_t> ExpandMxDequantInt8(const uint256& seed, uint32_t rows,
                                                      uint32_t cols);
/** Padded-pow2 leaf hashes for a round stream (R.4.2). */
[[nodiscard]] std::vector<uint256> BuildTileTreeLeaves(const std::vector<int8_t>& stream,
                                                       uint32_t t_leaf);
[[nodiscard]] uint256 BuildTileTreeRoot(const std::vector<int8_t>& stream, uint32_t t_leaf);
[[nodiscard]] RCMerkleProof OpenMerkleProof(const std::vector<uint256>& leaves, uint32_t index);
[[nodiscard]] bool VerifyMerkleProof(const uint256& leaf_hash, uint32_t index,
                                     const RCMerkleProof& proof, const uint256& root);
/** Hash leaf bytes from stream[index] and verify the Merkle path to round_root. */
[[nodiscard]] bool VerifyRCLeafOpening(const std::vector<int8_t>& stream, uint32_t t_leaf,
                                       uint32_t leaf_index, const uint256& round_root);
/** Structural total-MAC count (R.4.4) — nonce-independent. */
[[nodiscard]] uint64_t TotalRCEpisodeMacs(const RCEpisodeParams& p);

/** Oracle wgrad: G·Xᵀ → int64 (d_model × d_model). */
[[nodiscard]] std::vector<int64_t> TestHelperGemmGXtInt64(const std::vector<int8_t>& G,
                                                         const std::vector<int8_t>& X,
                                                         uint32_t b_seq, uint32_t d_model);

/** Chunked ExactGemmS8S8 wgrad path (panels of kRCWgradExactChunk). Must match
 *  TestHelperGemmGXtInt64 byte-for-byte. Optional `gemm` verified vs CPU. */
[[nodiscard]] std::vector<int64_t> TestHelperGemmGXtViaChunkedExact(
    const std::vector<int8_t>& G, const std::vector<int8_t>& X, uint32_t b_seq,
    uint32_t d_model, const matmul::v4::lt::ExactGemmBackend& gemm = {});

/** Segmented wgrad: returns per-kRCSegLen int64 partials whose sum equals
 *  TestHelperGemmGXtInt64. */
[[nodiscard]] std::vector<std::vector<int64_t>> TestHelperGemmGXtSegmented(
    const std::vector<int8_t>& G, const std::vector<int8_t>& X, uint32_t b_seq,
    uint32_t d_model);

/** Bytes of one Phase-1 Z segment partial (n_q × d_head int64 LE). */
[[nodiscard]] inline size_t RCSegZBytes(const RCEpisodeParams& p)
{
    return static_cast<size_t>(p.n_q) * p.d_head * sizeof(int64_t);
}
/** Bytes of one Phase-2 D segment partial (d_model × d_model int64 LE). */
[[nodiscard]] inline size_t RCSegDBytes(const RCEpisodeParams& p)
{
    return static_cast<size_t>(p.d_model) * p.d_model * sizeof(int64_t);
}
[[nodiscard]] inline uint32_t RCNumSegs(uint32_t k_len)
{
    return k_len == 0 ? 0u : (k_len + kRCSegLen - 1u) / kRCSegLen;
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_H
