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
/** FFN inner (up-projection) width — the standard transformer 4× expansion.
 *  Fused-FFN episode (scratchpad/fused-ffn-episode-design.md): each layer is
 *  X[l+1] = Extract(Extract(X[l]·W_up)·W_down + X[l]) with H = X[l]·W_up of
 *  width d_ff. Only X[l+1] (b_seq×d_model) is committed; H is recomputed by the
 *  verifier. Margin = MAC/committed-byte = 2·d_ff ≈ 5.1× the ~6400 knee. */
inline constexpr uint32_t kRCFfnDim = 4 * kRCModelDim; // 16384
static_assert(kRCFfnDim % 32 == 0, "kRCFfnDim must be divisible by 32 (MX align)");
static_assert(kRCFfnDim != 0, "kRCFfnDim must be non-zero");

/**
 * Datacenter-scale episode profile (ADDITIVE — governance-gated, OFF by default).
 * scratchpad/datacenter-episode-dimensions-design.md §3 / §6.1(A). Scales the
 * episode through the free extensive axes (depth = rounds×L_lyr, batch = b_seq);
 * the intensive GEMM dims (d_head, n_q, n_ctx, d_model) are held at epoch-0 so the
 * int64/int32 accumulator invariants are unchanged. F_ep grows ~16× (FFN 2·4·2=16×;
 * attention 2×). Selected only when Consensus::Params::nMatMulRCProfile == 2
 * (regtest/testnet override); mainnet keeps nMatMulRCHeight = INT32_MAX.
 *
 * HARDWARE-ALIGNMENT LEVER (aicompute-alignment-review.md §4, the weakest link).
 * T_leaf IS raised for the datacenter profile (kRCTileLeafBytesDC): a larger leaf
 * amortizes the tile-tree's internal-node + SHA-padding overhead over more GEMM
 * bytes, so FEWER SHA compressions occur per committed GEMM byte, widening the
 * compute/hash margin off the ~1× knee (§4 "raise T_leaf … fewer compressions per
 * GEMM FLOP"). The raise is bounded (the leaf-content hash is T_leaf-invariant, so
 * the T_leaf lever caps near the ~6% internal-node overhead) and trades against the
 * sampled-carrier opening cost (each opened leaf relays T_leaf bytes); the residual
 * toward the review's 2–4× target is the GEMM-based digest (future). T_leaf stays
 * MX-block-aligned (%32) and %64==0 so segment openings still bind cleanly to leaves.
 */
inline constexpr uint32_t kRCRoundsDC = 8;     // 2× epoch-0 rounds (depth)
// Fused-FFN datacenter dims (scratchpad/fused-ffn-episode-design.md §Dimensioning).
// SCALE LEVER = b_seq (batch), NOT L_lyr: L raises the sampleable-unit count
// N = rounds·(1+L), which would push λ·(per-unit bytes) over the 12 MiB carrier
// ceiling (L=64 ⇒ N=520 ⇒ ~27 MiB) and weaken exhaustive layer coverage. b_seq
// raises MAC with N, λ, carrier bytes and per-tile verify-cost all HELD (width
// unpin), so it is the free compute lever; d_ff is the margin lever (gated by
// verify time). L_lyr stays 24 (N = 8·25 = 200, λ = min(512,200) = 200: every
// unit sampled). b_seq is raised to restore the intended ~16× datacenter/base
// differential against the (now fused-FFN, heavier) base:
//   MAC_dc   = 2^37·16422 = 2 257 022 493 917 184  (~2.257 PMAC, ~16× base)
//   MAC_base = 2^37·1027   =   141 149 805 215 744
//   exact reduced ratio = 16422/1027 = 15.990× (drives the ASERT rescale).
inline constexpr uint32_t kRCLayersDC = 24;    // fused-FFN depth (N=200, λ exhaustive)
inline constexpr uint32_t kRCBatchSeqDC = 87'552; // = 2736·32 (MX-aligned); ~16× ratio lever
inline constexpr uint32_t kRCFfnDimDC = 4 * kRCModelDim; // 16384 (transformer 4× expansion)
inline constexpr uint32_t kRCTileLeafBytesDC = 4096; // 4× epoch-0 (compute/hash margin)
static_assert(kRCBatchSeqDC % 32 == 0, "kRCBatchSeqDC must be divisible by 32 (MX align)");
static_assert(kRCFfnDimDC % 32 == 0 && kRCFfnDimDC != 0,
              "kRCFfnDimDC must be non-zero and MX(32)-aligned");
static_assert(kRCRoundsDC != 0 && kRCLayersDC != 0, "datacenter depth axes must be non-zero");
static_assert(kRCTileLeafBytesDC % 32 == 0 && kRCTileLeafBytesDC % 64 == 0,
              "kRCTileLeafBytesDC must be MX(32)- and SHA-block(64)-aligned for leaf binding");
static_assert(kRCTileLeafBytesDC >= kRCTileLeafBytes,
              "datacenter T_leaf must not shrink the epoch-0 leaf (compute/hash lever raises it)");

/** Max |s8| operand magnitude on the RC ExactGemm path (balanced M11×2^{e≤3}). */
inline constexpr int32_t kRCMxOperandAbsMax = 48; // 6 * 2^3
/** Phase-2 fwd/bwd ExactGemm is s8×s8→int32 before Extract; keep |acc| < 2^31. */
static_assert(static_cast<uint64_t>(kRCModelDim) *
                      (static_cast<uint64_t>(kRCMxOperandAbsMax) * kRCMxOperandAbsMax) +
                  static_cast<uint64_t>(kRCMxOperandAbsMax) < (uint64_t{1} << 31),
              "Phase-2 int32 GEMM+Extract needs |acc| < 2^31 at epoch-0 d_model");
/** Fused-FFN down GEMM (H·W_down) contracts over d_ff (4× d_model); the int32
 *  Extract path still needs |acc| < 2^31 including the +X[l] residual. */
static_assert(static_cast<uint64_t>(kRCFfnDim) *
                      (static_cast<uint64_t>(kRCMxOperandAbsMax) * kRCMxOperandAbsMax) +
                  static_cast<uint64_t>(kRCMxOperandAbsMax) < (uint64_t{1} << 31),
              "Fused-FFN down GEMM (k=d_ff) int32 Extract needs |acc| < 2^31");

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

/**
 * Transcript serialization version (FINAL-FORM A1 / F7).
 * ENC_RC_V1 = current V1 stream layout with kRCSegmentLeavesEnabled=false.
 * Frozen toy golden: 5b1bff3c835b1c8e7816a2cccb181eb2fc30a99d97a971d73108c52a8238acd4
 * (MakeToyRCEpisodeParams + MakeRCHeader(42)).
 *
 * Silent golden replacement is FORBIDDEN. Bumping the *active* default
 * (`kRCTranscriptVersion`) is REQUIRED before any frozen digest may change.
 * Versioned domain tags (BTX_RC_*_V1/V2/V3) must not collide across versions;
 * KEEP V1+V2+V3 goldens in tests / CI (see contrib/matmul-v4/rc-golden-gate.py).
 *
 * Episode path default remains V1. Coupled V3 carries `transcript_version=3`
 * via RCCoupOptions / RCCoupConsensusConfig (independent COUP_*_V3 domains).
 */
inline constexpr uint32_t ENC_RC_V1 = 1;
inline constexpr uint32_t ENC_RC_V2 = 2;
inline constexpr uint32_t ENC_RC_V3 = 3;
inline constexpr uint32_t ENC_RC_V4 = 4;
inline constexpr uint32_t kRCTranscriptVersion = ENC_RC_V1;
static_assert(kRCTranscriptVersion == ENC_RC_V1,
              "kRCTranscriptVersion must equal ENC_RC_V1 while V1 is active");

/** Domain-separation tags (frozen byte strings — R.4). ENC_RC_V1 tags. */
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
    uint32_t d_ff{kRCFfnDim}; // fused-FFN inner width (up: d_model×d_ff, down: d_ff×d_model)
    uint32_t b_seq{kRCBatchSeq};
    uint32_t T_leaf{kRCTileLeafBytes};
};

/** Optional execution knobs that MUST NOT change digests (R.2.2 / R.3.3).
 *  Stage B planners (RCExecMode in matmul_v4_rc_transcript.h) map onto these
 *  via OptionsForExecMode — Resident/Checkpointed/Streamed MUST NOT change
 *  digests. */
struct RCEpisodeOptions {
    /** Phase-1 n_ctx tile length. 0 ⇒ whole context. Any positive ΔT is
     *  allowed (§R.2.2): incomplete MX 32-blocks are buffered across tile
     *  windows so Extract boundaries stay on bj = ⌊t/32⌋. */
    uint32_t phase1_tile_delta{0};
    enum class Checkpoint : uint8_t {
        StoreAll = 0,     // reference default / RCExecMode::Resident
        StoreEvery4 = 1,  // recompute missing activations / Checkpointed
        StoreOnlyX0 = 2,  // recompute all forward from X[0] / Streamed
    };
    /** Checkpoint schedule for Phase-2 activations. StoreOnlyX0 / StoreEvery4
     *  actually drop non-checkpoint X layers (P1.1) and recompute on demand;
     *  digests stay identical to StoreAll. Prefer StoreOnlyX0 on memory-tight
     *  hosts. Default remains StoreAll for peak-throughput reference runs. */
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
     *  (X[l+1] ‖ G[l] ‖ [D_seg0..D_segM LE int64] ‖ D_int8).
     *  The consensus episode path (out_rounds == nullptr) streams these bytes
     *  into the Merkle tree without retaining the full buffer (P1.1). */
    std::vector<int8_t> stream{};
};

/** Merkle opening: siblings from leaf toward root (index parity selects side). */
struct RCMerkleProof {
    std::vector<uint256> siblings{};
};

[[nodiscard]] bool ValidateRCEpisodeParams(const RCEpisodeParams& p);

/** Epoch-0 consensus dims: EpisodeParamsFromScale({kRCW0Res, kRCW0Cap}). */
[[nodiscard]] RCEpisodeParams DefaultConsensusRCEpisodeParams();
/** Datacenter-scale profile (nMatMulRCProfile==2): the epoch-0 base dims with
 *  ONLY rounds/L_lyr/b_seq raised (kRCRoundsDC/kRCLayersDC/kRCBatchSeqDC). All
 *  intensive dims (d_head, n_q, n_ctx, d_model, T_leaf) copied unchanged from
 *  DefaultConsensusRCEpisodeParams so it passes ValidateRCEpisodeParams and the
 *  epoch invariants. ADDITIVE / governance-gated — see
 *  scratchpad/datacenter-episode-dimensions-design.md §6.1(A). */
[[nodiscard]] RCEpisodeParams MakeDatacenterRCEpisodeParams();
/** Tiny dims for unit tests — every matrix dim divisible by 32 (H13). */
[[nodiscard]] RCEpisodeParams MakeToyRCEpisodeParams();
/** Medium dims for self-qual: wgrad contraction exceeds 2^24 (b_seq ≥ 8192). */
[[nodiscard]] RCEpisodeParams MakeMediumRCEpisodeParams();
/** Alias of DefaultConsensusRCEpisodeParams — provisional frozen production episode
 *  (n_ctx=786432 …). Harness `--production`; height stays disabled. */
[[nodiscard]] RCEpisodeParams MakeProductionRCEpisodeParams();
/** M9 cost-ladder rung (b_seq=256) between toy and medium — off-CI prove. */
[[nodiscard]] RCEpisodeParams MakeCostLadderRCEpisodeParams();
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
 *  Consensus REJECT / spot-check MUST pass an empty backend.
 *  Malformed params (ValidateRCEpisodeParams false) → null digest (reject, no assert). */
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
[[nodiscard]] std::vector<int8_t> ExpandMxDequantInt8Parallel(const uint256& seed, uint32_t rows,
                                                              uint32_t cols, uint32_t threads);
/** Padded-pow2 leaf hashes for a round stream (R.4.2). */
[[nodiscard]] std::vector<uint256> BuildTileTreeLeaves(const std::vector<int8_t>& stream,
                                                       uint32_t t_leaf);
[[nodiscard]] uint256 BuildTileTreeRoot(const std::vector<int8_t>& stream, uint32_t t_leaf);

/**
 * Streaming tile-tree absorber (P1.1): hash T_leaf-sized chunks into Merkle
 * leaves without retaining the full round byte stream. Byte-identical to
 * BuildTileTreeLeaves / BuildTileTreeRoot over the same concatenation.
 *
 * Residual (honest): streaming removes the ~2.25 GiB/round serialized copy and
 * checkpoint modes no longer rebuild every X before hashing. Production-dim
 * Phase-2 still holds W + G[0..L-1] + D[0..L-1] (+ GEMM temps) during the
 * backward pass — measured RSS below is for toy / modest custom params only;
 * do not treat those numbers as a production-dim 8 GB proof.
 */
class RoundMerkleStream {
public:
    explicit RoundMerkleStream(uint32_t t_leaf);
    void Absorb(const int8_t* data, size_t len);
    void Absorb(const std::vector<int8_t>& v) { Absorb(v.data(), v.size()); }
    /** Append int64 matrix as little-endian bytes (segment-leaf layout). */
    void AbsorbInt64LE(const std::vector<int64_t>& M);
    /** Finalize last partial leaf (zero-pad) + pow2 pad leaves; return leaves. */
    [[nodiscard]] std::vector<uint256> FinalizeLeaves();
    [[nodiscard]] uint256 FinalizeRoot();
    [[nodiscard]] size_t BytesAbsorbed() const { return m_absorbed; }

private:
    uint32_t m_t_leaf{0};
    size_t m_absorbed{0};
    std::vector<unsigned char> m_partial;
    std::vector<uint256> m_leaves;
    bool m_finalized{false};
    void EmitLeaf(const unsigned char* leaf_bytes);
};
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
