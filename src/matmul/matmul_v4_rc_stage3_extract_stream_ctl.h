// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EXTRACT_STREAM_CTL_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EXTRACT_STREAM_CTL_H

#include <matmul/matmul_v4_rc_stage3_ctl.h>
#include <matmul/matmul_v4_rc_stage3_episode_extract_product.h>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3ExtractStreamCtlVersion = 1;
inline constexpr uint32_t kRCStage3ExtractStreamCtlBusId =
    0x45531914U; // "ES" + endpoints 19/14

/**
 * Exact endpoint-14 -> endpoint-19 relation for one streamed 32-cell tile.
 *
 * The producer proof re-executes the canonical sampler AIR and appends its
 * dual LogUp columns to kColOut in the same quotient trace. The consumer
 * re-executes the owning semantic-memory shard and appends the opposing
 * LogUp columns directly to kRCStage3EpisodeMemoryExport. Only the exact
 * verifier-derived 32-row intervals are active; no detached value mirror is
 * accepted.
 */
struct RCStage3ExtractStreamCtlTileProof {
    uint16_t version{kRCStage3ExtractStreamCtlVersion};
    uint32_t global_stream_tile{0};
    uint32_t extract_tile_ordinal{0};
    uint32_t round_index{0};
    uint32_t memory_shard_index{0};
    uint32_t memory_row_begin{0};
    uint256 statement_commitment{};
    uint256 extract_collection_commitment{};
    uint256 tile_stream_collection_commitment{};
    uint256 sampler_output_root{};
    uint256 memory_value_root{};
    RCStage3CtlManifest manifest;
    std::vector<RCStage3CtlChildPin> pins;
    air_quotient::AirQuotientProof<gkr_field::Fp3>
        producer_product;
    air_quotient::AirQuotientProof<gkr_field::Fp3>
        consumer_product;
    uint256 producer_product_commitment{};
    uint256 consumer_product_commitment{};
    uint256 proof_commitment{};
};

struct RCStage3ExtractStreamCtlProof {
    uint16_t version{kRCStage3ExtractStreamCtlVersion};
    uint256 statement_commitment{};
    uint256 extract_collection_commitment{};
    uint256 tile_stream_collection_commitment{};
    std::vector<RCStage3ExtractStreamCtlTileProof> tiles;
    uint256 collection_commitment{};
};

/**
 * Streaming child constructor/verifier. These execute the complete augmented
 * relation traces for one canonical tile but deliberately do not re-run the
 * parent products. Aggregate callers must first execute the Extract and
 * tile-stream products, as Prove/VerifyRCStage3ExtractStreamCtl do.
 */
[[nodiscard]] bool ProveRCStage3ExtractStreamCtlTile(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t global_stream_tile,
    RCStage3ExtractStreamCtlTileProof& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3ExtractStreamCtlTile(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t global_stream_tile,
    const RCStage3ExtractStreamCtlTileProof& proof,
    std::string* why = nullptr);

[[nodiscard]] bool ProveRCStage3ExtractStreamCtl(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    RCStage3ExtractStreamCtlProof& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3ExtractStreamCtl(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    const RCStage3ExtractStreamCtlProof& proof,
    std::string* why = nullptr);

/**
 * Native selected-CTL AirConstraintSystem for one 32-cell tile (gamma/alpha
 * baked as closure constants, gamma-power tuple NS + gamma*tile + gamma^2*addr
 * + gamma^3*value). Exposed so the constraint-bytecode transport-lane migration
 * can be DIFFERENTIALLY tested against the exact native relation. Twelve
 * constraints (two lanes x {mask-boolean, inverse, inverse-inactive,
 * running-first/transition/last}). Column layout: source at `source_column`,
 * then mask, address, inverse1, inverse2, running1, running2 appended after
 * `base_columns`. Only the constraints are built (no witness columns), so
 * arbitrary challenges/terminal are accepted.
 */
[[nodiscard]] air_quotient::AirConstraintSystem<gkr_field::Fp3>
BuildRCStage3ExtractStreamSelectedCtlConstraintSystem(
    uint32_t base_columns,
    uint32_t n_rows,
    uint32_t source_column,
    uint32_t tile,
    int8_t multiplicity,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal);

} // namespace matmul::v4::rc

#endif
