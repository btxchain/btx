// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_TRANSCRIPT_H
#define BTX_MATMUL_MATMUL_V4_RC_TRANSCRIPT_H

#include <matmul/matmul_v4_rc.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

// ENC_RC Stage B — bounded-memory transcript sinks + non-consensus planners.
// Normative: FINAL-FORM Stage B. Digests:
//   V1 (default / ENC_RC): fused-FFN flat tile-tree stream.
//   V2 (typed subroots): for Stage C coupled puzzle ONLY; new domain tags.

namespace matmul::v4::rc {

/** Frozen transcript serialization version. Silent golden replacement forbidden.
 *  Bump only with new domain tags AND retain prior goldens. */
inline constexpr uint8_t kRCTranscriptVersionV1 = 1;
inline constexpr uint8_t kRCTranscriptVersionV2 = 2;
inline constexpr uint8_t kRCTranscriptVersionV3 = 3;
// Default sink version equals V1. Do NOT redefine kRCTranscriptVersion here —
// that symbol is the uint32_t ENC_RC transcript gate in matmul_v4_rc.h (A1).
static_assert(kRCTranscriptVersionV1 == 1 && kRCTranscriptVersion == 1,
              "sink V1 must match ENC_RC kRCTranscriptVersion while V1 is active");
static_assert(kRCTranscriptVersionV3 == ENC_RC_V3,
              "sink V3 must match ENC_RC_V3");

/** Domain tags for V2 typed subroots (Stage C). Never used by ENC_RC V1 path. */
inline constexpr char kRCRoundRootV2Tag[] = "BTX_RC_ROUND_ROOT_V2";
inline constexpr char kRCSegCommitV2Tag[] = "BTX_RC_SEG_V2";
inline constexpr char kRCPhaseCommitV2Tag[] = "BTX_RC_PHASE_V2";
inline constexpr char kRCLayerCommitV2Tag[] = "BTX_RC_LAYER_V2";

/** Segment / tensor kinds submitted through RCTranscriptSink. */
enum class RCSegType : uint8_t {
    ZPartial = 0,   // Phase-1 int64 segment partial (LE bytes)
    ZExtracted = 1, // Phase-1 Extracted int8 Z
    XAct = 2,       // Phase-2 activation X[l+1]
    GGrad = 3,      // Phase-2 feature grad G[l]
    DPartial = 4,   // Phase-2 int64 wgrad segment partial
    DExtracted = 5, // Phase-2 Extracted int8 D[l]
};

/**
 * Non-consensus execution planner. MUST NOT change any committed digest byte.
 * Maps onto existing RCEpisodeOptions::Checkpoint / phase1_tile_delta.
 */
enum class RCExecMode : uint8_t {
    Resident = 0,     // full activations resident (StoreAll)
    Checkpointed = 1, // StoreEvery4 + recompute
    Streamed = 2,     // StoreOnlyX0 + bounded page window
};

/** Build episode options for an exec mode (digest-invariant). */
[[nodiscard]] RCEpisodeOptions OptionsForExecMode(RCExecMode mode,
                                                  uint32_t phase1_tile_delta = 0);

/**
 * Canonical transcript sink (Stage B1). Episode / coupled-puzzle producers
 * push ordered segments; sinks produce round_root without requiring a
 * monolithic SerializeRoundStream vector.
 */
struct RCTranscriptSink {
    virtual ~RCTranscriptSink() = default;
    virtual void BeginRound(uint32_t r) = 0;
    virtual void BeginPhase(uint32_t phase) = 0;
    virtual void BeginLayer(uint32_t layer) = 0;
    virtual void SubmitSegment(RCSegType type, uint32_t layer, uint32_t seg_id,
                               Span<const unsigned char> canonical_bytes) = 0;
    virtual void SubmitExtractedTensor(RCSegType type, uint32_t layer,
                                       Span<const int8_t> tensor) = 0;
    virtual void EndLayer() = 0;
    virtual void EndPhase() = 0;
    /** Finalize the round; returns round_root. */
    virtual uint256 EndRound() = 0;
};

/**
 * O(log leaf_count) incremental Merkle frontier for RC tile-tree nodes.
 * Byte-identical root to FoldTileTreeRoot over the same leaf sequence
 * (after pow2 pad). Does not retain leaf hashes.
 */
class RCMerkleFrontier {
public:
    RCMerkleFrontier() = default;
    void Reset();
    void AppendLeaf(const uint256& leaf_hash);
    /** Pad with pad_leaf to next power of two, then return root. */
    [[nodiscard]] uint256 FinalizeRoot(const uint256& pad_leaf);
    [[nodiscard]] size_t LeafCount() const { return m_leaf_count; }
    /** Soft memory: frontier slots ≤ ceil(log2(leaf_count+1))+1. */
    [[nodiscard]] size_t FrontierSlots() const;

private:
    std::vector<std::optional<uint256>> m_frontier;
    size_t m_leaf_count{0};
};

/**
 * Streaming sink (Stage B2): bounded absorb window + O(log n) frontier.
 * Discards segment / tensor bytes after absorb. V1 flat mode matches
 * RoundMerkleStream / BuildTileTreeRoot. V2 uses typed domain-separated
 * subroots (Stage C).
 */
class RCStreamingSink final : public RCTranscriptSink {
public:
    explicit RCStreamingSink(uint32_t t_leaf,
                             uint8_t version = kRCTranscriptVersionV1);
    ~RCStreamingSink() override;
    RCStreamingSink(RCStreamingSink&&) noexcept;
    RCStreamingSink& operator=(RCStreamingSink&&) noexcept;
    RCStreamingSink(const RCStreamingSink&) = delete;
    RCStreamingSink& operator=(const RCStreamingSink&) = delete;

    void BeginRound(uint32_t r) override;
    void BeginPhase(uint32_t phase) override;
    void BeginLayer(uint32_t layer) override;
    void SubmitSegment(RCSegType type, uint32_t layer, uint32_t seg_id,
                       Span<const unsigned char> canonical_bytes) override;
    void SubmitExtractedTensor(RCSegType type, uint32_t layer,
                               Span<const int8_t> tensor) override;
    void EndLayer() override;
    void EndPhase() override;
    uint256 EndRound() override;

    [[nodiscard]] uint8_t Version() const;
    [[nodiscard]] size_t BytesAbsorbed() const;
    /** Peak partial-window + frontier footprint (soft accounting, bytes). */
    [[nodiscard]] size_t SoftWorkingSetBytes() const;

private:
    struct Impl;
    uint32_t m_t_leaf{0};
    uint8_t m_version{kRCTranscriptVersionV1};
    std::unique_ptr<Impl> m_impl;
};

/**
 * Resident sink (Stage B2): same root algorithm as RCStreamingSink, but
 * retains leaf hashes (and optionally page bytes) for multi-episode /
 * spot-check openings.
 */
class RCResidentSink final : public RCTranscriptSink {
public:
    explicit RCResidentSink(uint32_t t_leaf, uint8_t version = kRCTranscriptVersionV1,
                            bool retain_pages = true);
    ~RCResidentSink() override;
    RCResidentSink(RCResidentSink&&) noexcept;
    RCResidentSink& operator=(RCResidentSink&&) noexcept;
    RCResidentSink(const RCResidentSink&) = delete;
    RCResidentSink& operator=(const RCResidentSink&) = delete;

    void BeginRound(uint32_t r) override;
    void BeginPhase(uint32_t phase) override;
    void BeginLayer(uint32_t layer) override;
    void SubmitSegment(RCSegType type, uint32_t layer, uint32_t seg_id,
                       Span<const unsigned char> canonical_bytes) override;
    void SubmitExtractedTensor(RCSegType type, uint32_t layer,
                               Span<const int8_t> tensor) override;
    void EndLayer() override;
    void EndPhase() override;
    uint256 EndRound() override;

    [[nodiscard]] uint8_t Version() const;
    [[nodiscard]] const std::vector<uint256>& Leaves() const;
    [[nodiscard]] const std::vector<std::vector<unsigned char>>& Pages() const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

/** Pad-leaf hash (identical to RoundMerkleStream / R.4.2). */
[[nodiscard]] uint256 RCTranscriptPadLeafHash();

/** Fold a power-of-two leaf vector (identical to episode FoldTileTreeRoot). */
[[nodiscard]] uint256 RCTranscriptFoldRoot(std::vector<uint256> level);

/**
 * Materialized V1 flat root over concatenated bytes (equivalence oracle for
 * incremental frontier). Identical to BuildTileTreeRoot.
 */
[[nodiscard]] uint256 RCTranscriptMaterializedFlatRoot(Span<const int8_t> stream,
                                                       uint32_t t_leaf);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_TRANSCRIPT_H
