// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_STREAMING_EPISODE_CLOSURE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_STREAMING_EPISODE_CLOSURE_H

#include <matmul/matmul_v4_rc_stage3_episode_external_producer_aggregate.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace matmul::v4::rc::streaming_episode_closure {

namespace aggregate = episode_external_producer_aggregate;
namespace source = episode_semantic_source_alg;

inline constexpr uint16_t kScheduleVersionV1 = 1;
inline constexpr uint16_t kLayerVersionV1 = 1;

/**
 * Immutable pre-episode schedule.
 *
 * The ordinary GEMM/Extract manifest also contains value and proof roots that
 * cannot exist until their layer has executed.  Binding an online child proof
 * to that late-bound manifest creates a circular dependency and forces the
 * prover to retain the whole episode.  This schedule commits only the exact
 * canonical Lambda(params) geometry and global intervals under the V3
 * statement precommitment.  Extract PRF keys for round r>0 depend on the
 * preceding round root, so they cannot honestly appear in this precommit.
 * Each actual PRF key and the per-layer value roots are committed by
 * StreamedLayerClosureV1 after that layer executes.
 */
struct ImmutableEpisodeScheduleV1 {
    uint16_t version{kScheduleVersionV1};
    uint256 statement_commitment{};
    RCEpisodeParams params{};
    std::vector<RCStage3GemmExtractLayerManifest> layers;
    uint64_t total_gemm_cells{0};
    uint64_t total_extract_tiles{0};
    uint256 schedule_commitment{};

};

/**
 * Durable proof-only result retained after one native layer is discarded.
 *
 * `consumer_bundle` owns the canonical ordinary Alg-FRI leaves.  `closure`
 * owns the four external-producer/GEMM rational-identity proof trees.  The
 * Y root is equality-proved against the ordinary GEMM leaf.  The nonlinear
 * Extract role is deliberately not claimed here; its callback-time child
 * proof must be attached by the normalized parent before authority.  No
 * A/B/Y/residual/Extract byte vector is retained.
 */
struct StreamedLayerClosureV1 {
    uint16_t version{kLayerVersionV1};
    uint32_t layer_ordinal{0};
    source::LayerShapeV1 shape;
    uint32_t consumer_leaf_begin{0};
    source::LayerBundleV1 consumer_bundle;
    aggregate::LayerClosureV1 closure;
    uint256 extract_prf{};
    uint256 gemm_y_vector_root_alg{};
    uint256 retained_commitment{};
    bool extract_role_proof_consumed{false};
    bool production_authority{false};

};

inline constexpr uint16_t kReceiptVersionV1 = 1;

/** Immutable handoff from mining callbacks to the normalized parent. */
struct StreamingEpisodeClosureReceiptV1 {
    uint16_t version{kReceiptVersionV1};
    ImmutableEpisodeScheduleV1 schedule;
    std::vector<StreamedLayerClosureV1> layers;
    std::vector<uint256> round_roots;
    uint256 episode_digest{};
    uint256 receipt_commitment{};
    bool every_gemm_child_verified{false};
    bool extract_role_children_consumed{false};
    bool normalized_parent_consumed{false};
    bool production_authority{false};
};

[[nodiscard]] bool BuildImmutableEpisodeScheduleV1(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    ImmutableEpisodeScheduleV1& out,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeImmutableEpisodeScheduleCommitmentV1(
    const ImmutableEpisodeScheduleV1& schedule);

/** Re-enumerate Lambda(params) and reject any noncanonical layer or binding. */
[[nodiscard]] bool ValidateImmutableEpisodeScheduleV1(
    const ImmutableEpisodeScheduleV1& schedule,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeStreamedLayerClosureCommitmentV1(
    const StreamedLayerClosureV1& layer);

[[nodiscard]] uint256
ComputeStreamingEpisodeClosureReceiptCommitmentV1(
    const StreamingEpisodeClosureReceiptV1& receipt);

/**
 * Proof-only verification of one retained layer.  The verifier supplies the
 * immutable schedule and replays every child proof; no native tensor is an
 * input.
 */
[[nodiscard]] bool VerifyStreamedLayerClosureV1(
    const ImmutableEpisodeScheduleV1& schedule,
    uint32_t expected_consumer_leaf_begin,
    const StreamedLayerClosureV1& layer,
    std::string* why = nullptr);

/**
 * Online sink for the exact v4.6-3 miner callback order.
 *
 * A layer is proved synchronously when its final Extract callback arrives,
 * then its native vectors are erased.  Only proof objects and roots survive.
 * Streamed SV/DOWN outputs are absorbed directly into the round Merkle
 * accumulator before erasure.  Missing, duplicated or reordered callbacks
 * poison the sink permanently.
 */
class StreamingEpisodeClosureSink final
    : public RCEpisodeProofWitnessSink {
public:
    StreamingEpisodeClosureSink(
        const RCStage3SuccinctProof& statement,
        const RCEpisodeParams& params);

    void OnPhase1Operands(
        const RCPhase1OperandsWitnessView& view) override;
    void OnPhase1QKtTile(
        const RCPhase1QKtTileWitnessView& view) override;
    void OnPhase1SVRow(
        const RCPhase1SVRowWitnessView& view) override;
    void OnFfnGemm(
        const RCFfnGemmWitnessView& view) override;
    void OnFfnExtract(
        const RCFfnExtractWitnessView& view) override;
    void OnRoundRoot(
        uint32_t round_ordinal,
        const uint256& round_root) override;
    void OnEpisodeDigest(
        const uint256& episode_digest) override;

    [[nodiscard]] bool Complete(
        std::string* why = nullptr) const;

    [[nodiscard]] bool BuildReceipt(
        StreamingEpisodeClosureReceiptV1& out,
        std::string* why = nullptr) const;

    [[nodiscard]] const ImmutableEpisodeScheduleV1&
    Schedule() const
    {
        return m_schedule;
    }

    [[nodiscard]] const std::vector<StreamedLayerClosureV1>&
    Layers() const
    {
        return m_finalized;
    }

    [[nodiscard]] const std::vector<uint256>&
    RoundRoots() const
    {
        return m_round_roots;
    }

    [[nodiscard]] const uint256& EpisodeDigest() const
    {
        return m_episode_digest;
    }

    /** Structural audit aid: bytes of native vectors still retained. */
    [[nodiscard]] uint64_t RetainedNativeBytes() const;
    [[nodiscard]] uint64_t PeakRetainedNativeBytes() const
    {
        return m_peak_retained_native_bytes;
    }

private:
    struct PendingLayerV1 {
        RCStage3EpisodeGemmLayerProduct layer;
        RCStage3EpisodeExtractProduct extract;
        std::vector<int8_t> extract_output;
        uint256 extract_prf{};
        uint64_t next_tile{0};
        bool operands_seen{false};
        bool gemm_seen{false};
        bool extract_seen{false};
    };

    void Reject(const std::string& detail);
    void UpdatePeakRetainedBytes();
    [[nodiscard]] uint32_t RoundBase(uint32_t round) const;
    [[nodiscard]] uint32_t FfnOrdinal(
        uint32_t round,
        uint32_t layer,
        RCFfnProjection projection) const;
    [[nodiscard]] bool AppendExtract(
        uint32_t ordinal,
        const int64_t* input,
        const int8_t* output,
        uint64_t cells,
        const uint256& prf);
    [[nodiscard]] bool FinalizeLayer(uint32_t ordinal);

    ImmutableEpisodeScheduleV1 m_schedule;
    RCGkrLayout m_layout;
    std::vector<PendingLayerV1> m_pending;
    std::vector<StreamedLayerClosureV1> m_finalized;
    std::vector<uint256> m_round_roots;
    std::unique_ptr<RoundMerkleStream> m_round_merkle;
    uint32_t m_next_finalized_layer{0};
    uint32_t m_next_consumer_leaf{0};
    uint256 m_episode_digest{};
    uint64_t m_peak_retained_native_bytes{0};
    bool m_episode_digest_seen{false};
    std::string m_error;
};

[[nodiscard]] bool VerifyStreamingEpisodeClosureV1(
    const ImmutableEpisodeScheduleV1& schedule,
    const std::vector<StreamedLayerClosureV1>& layers,
    const std::vector<uint256>& round_roots,
    const uint256& episode_digest,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyStreamingEpisodeClosureReceiptV1(
    const StreamingEpisodeClosureReceiptV1& receipt,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::streaming_episode_closure

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_STREAMING_EPISODE_CLOSURE_H
