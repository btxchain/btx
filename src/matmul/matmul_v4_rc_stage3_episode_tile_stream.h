// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_TILE_STREAM_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_TILE_STREAM_H

#include <matmul/matmul_v4_rc_stage3_episode_round_roots.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3EpisodeTileStreamProductVersion = 1;
inline constexpr uint16_t kRCStage3EpisodeTileStreamLeafCtlVersion = 1;
inline constexpr uint32_t kRCStage3EpisodeTileStreamLeafCtlBusId =
    0x13140000U;

enum RCStage3EpisodeTileTreeByteBridgeColumn : uint32_t {
    kRCStage3EpisodeTileBridgeActive = 0,
    kRCStage3EpisodeTileBridgeAddress,
    kRCStage3EpisodeTileBridgeExpected,
    kRCStage3EpisodeTileBridgeValue,
    kRCStage3EpisodeTileBridgeExport,
    kRCStage3EpisodeTileBridgeByte,
    kRCStage3EpisodeTileBridgeSign,
    kRCStage3EpisodeTileBridgeBitBase,
    kRCStage3EpisodeTileBridgeColumns =
        kRCStage3EpisodeTileBridgeBitBase + 8,
};

/**
 * One canonical 32-byte Extract output tile.
 *
 * The verifier derives every identity field from Λ(params), executes `proof`,
 * and requires its proof-owned kColOut root to equal the commitment of the
 * corresponding signed-byte embedding of the TileTreeManifest stream.
 */
struct RCStage3EpisodeTileStreamShard {
    uint32_t global_stream_tile{0};
    uint32_t layer_ordinal{0};
    uint64_t layer_tile_index{0};
    uint64_t stream_byte_begin{0};
    RCStage3EpisodeAirPublicPin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> proof;
};

struct RCStage3EpisodeTileStreamRound {
    uint32_t round_index{0};
    RCStage3EpisodeRoundTileTreeProducer tree;
    /** Proof-owned, canonically addressed signed-byte stream for endpoint 19. */
    RCStage3EpisodeSemanticMemoryBundle stream_memory;
};

/**
 * Exact flat V1 product for endpoints 19--22.
 *
 * This is intentionally not advertised as succinct recursion: it executes one
 * sampler proof per streamed Extract tile, every stream-memory shard, and every
 * SHA boundary proof. It is the semantic reference product a recursive parent
 * must consume without weakening any equality.
 */
struct RCStage3EpisodeTileStreamProduct {
    uint16_t version{kRCStage3EpisodeTileStreamProductVersion};
    uint256 statement_commitment{};
    uint256 gemm_extract_manifest_commitment{};
    uint32_t expected_rounds{0};
    uint32_t expected_stream_tiles{0};
    std::vector<RCStage3EpisodeTileStreamShard> tiles;
    std::vector<RCStage3EpisodeTileStreamRound> rounds;
    uint256 collection_commitment{};
};

/**
 * Public statement for one endpoint-19 semantic-memory shard feeding the
 * endpoint-20 canonical leaf-preimage byte relation.
 *
 * VALUE uses the signed Extract embedding while BYTE is the unique octet
 * reconstructed in the consumer ProgramTable.  `value_root` is the root
 * already owned by the executed endpoint-19 memory proof.
 */
struct RCStage3EpisodeTileStreamLeafCtlPin {
    uint16_t version{kRCStage3EpisodeTileStreamLeafCtlVersion};
    uint256 statement_commitment{};
    uint256 tile_stream_collection_commitment{};
    uint256 tile_tree_manifest_commitment{};
    uint256 source_memory_manifest_commitment{};
    uint32_t round_index{0};
    uint32_t shard_index{0};
    uint64_t value_begin{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint256 value_root{};
    uint256 program_commitment{};
    uint256 pin_commitment{};

    bool operator==(
        const RCStage3EpisodeTileStreamLeafCtlPin&) const = default;
};

struct RCStage3EpisodeTileStreamLeafCtlShardProof {
    RCStage3EpisodeTileStreamLeafCtlPin bridge_pin;
    RCStage3CtlManifest manifest;
    RCStage3CtlSchedule producer_schedule;
    RCStage3CtlSchedule consumer_schedule;
    std::vector<RCStage3CtlChildPin> pins;
    air_quotient::AirQuotientProof<gkr_field::Fp3>
        producer_product;
    air_quotient::AirQuotientProof<gkr_field::Fp3>
        consumer_product;
    uint256 producer_product_commitment{};
    uint256 consumer_product_commitment{};
    uint256 proof_commitment{};
};

struct RCStage3EpisodeTileStreamLeafCtlProof {
    uint16_t version{kRCStage3EpisodeTileStreamLeafCtlVersion};
    uint256 statement_commitment{};
    uint256 tile_stream_collection_commitment{};
    std::vector<RCStage3EpisodeTileStreamLeafCtlShardProof> shards;
    uint256 collection_commitment{};
};

[[nodiscard]] bool
BuildRCStage3EpisodeTileTreeByteBridgeConstraintSystem(
    const RCStage3EpisodeTileStreamLeafCtlPin& pin,
    const std::vector<uint8_t>& bytes,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

/** Execute endpoint 19 and prove every signed stream-memory EXPORT cell is
 * the exact endpoint-20 leaf-preimage octet through opposing same-trace CTLs.
 */
[[nodiscard]] bool ProveRCStage3EpisodeTileStreamLeafCtl(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    RCStage3EpisodeTileStreamLeafCtlProof& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3EpisodeTileStreamLeafCtl(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    const RCStage3EpisodeTileStreamLeafCtlProof& proof,
    std::string* why = nullptr);

[[nodiscard]] bool RCStage3EpisodeLayerIsStreamed(
    RCGkrLayerKind kind);

/** Canonical V1 aggregate of every ordered proof-owned kColOut root in one
 * Extract layer. The tile-stream product invokes it for the consensus-streamed
 * subset; the complete Extract product invokes it for every layer. */
[[nodiscard]] uint256
ComputeRCStage3EpisodeStreamedLayerOutputRoot(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<uint256>& ordered_tile_output_roots);

[[nodiscard]] uint256
ComputeRCStage3EpisodeTileStreamCollectionCommitment(
    const RCStage3EpisodeTileStreamProduct& product);

/**
 * Exact structural schedule validation. No native SHA/episode replay occurs.
 * It rejects omitted, duplicated, reordered, resized, cross-round, or
 * non-streamed tiles and checks every per-layer output-root aggregate.
 */
[[nodiscard]] bool ValidateRCStage3EpisodeTileStreamSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeTileStreamProduct& product,
    std::string* why = nullptr);

/**
 * Execute all sampler, semantic-memory, leaf-hash, internal-hash, and root
 * proofs after validating the exact schedule and commitment equalities.
 */
[[nodiscard]] bool VerifyRCStage3EpisodeTileStreamProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeTileStreamProduct& product,
    std::string* why = nullptr);

struct RCStage3EpisodeTileStreamAudit {
    bool verifier_derived_emission_schedule{false};
    bool every_streamed_extract_shard_executed{false};
    bool extract_out_to_stream_byte_equality{false};
    bool proof_owned_stream_memory_executed{false};
    bool stream_to_leaf_same_trace_ctl_executable{false};
    bool every_leaf_hash_executed{false};
    bool leaf_to_internal_same_trace_ctl_executable{false};
    bool every_internal_hash_executed{false};
    bool internal_to_typed_root_same_trace_ctl_executable{false};
    bool canonical_round_root_derived{false};
    bool endpoints_19_through_22_locally_complete{false};
    bool all_extract_inputs_and_gemm_provenance_complete{false};
    bool recursively_consumed{false};
    bool transitively_complete{false};
    std::string remaining;
};

[[nodiscard]] RCStage3EpisodeTileStreamAudit
CurrentRCStage3EpisodeTileStreamAudit();

inline constexpr bool
    kRCStage3EpisodeTileStreamLocalRelationExecutable = true;
inline constexpr bool
    kRCStage3EpisodeTileStreamTransitivelyComplete = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_TILE_STREAM_H
