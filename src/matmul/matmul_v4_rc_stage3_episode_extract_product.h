// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_EXTRACT_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_EXTRACT_PRODUCT_H

#include <matmul/matmul_v4_rc_stage3_episode_tile_stream.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3EpisodeExtractProductVersion = 1;
inline constexpr uint32_t kRCStage3EpisodeExtractMixBits = 32;

enum RCStage3EpisodeExtractMixColumn : uint32_t {
    kRCStage3ExtractMixU = 0,
    kRCStage3ExtractMixQ,
    kRCStage3ExtractMixV,
    kRCStage3ExtractMixH,
    kRCStage3ExtractMixBranch,
    kRCStage3ExtractMixYLoBits,
    kRCStage3ExtractMixYHiBits =
        kRCStage3ExtractMixYLoBits + kRCStage3EpisodeExtractMixBits,
    kRCStage3ExtractMixUBits =
        kRCStage3ExtractMixYHiBits + kRCStage3EpisodeExtractMixBits,
    kRCStage3ExtractMixQBits =
        kRCStage3ExtractMixUBits + kRCStage3EpisodeExtractMixBits,
    kRCStage3ExtractMixVBits =
        kRCStage3ExtractMixQBits + kRCStage3EpisodeExtractMixBits,
    kRCStage3ExtractMixQDifferenceBits =
        kRCStage3ExtractMixVBits + kRCStage3EpisodeExtractMixBits,
    kRCStage3EpisodeExtractMixColumns =
        kRCStage3ExtractMixQDifferenceBits +
        kRCStage3EpisodeExtractMixBits,
};
static_assert(kRCStage3EpisodeExtractMixColumns == 197);

struct RCStage3EpisodeExtractMixPin {
    uint16_t version{kRCStage3EpisodeExtractProductVersion};
    uint256 statement_commitment{};
    uint32_t layer_ordinal{0};
    uint64_t layer_tile_index{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint32_t n_coeffs{0};
    std::vector<RCStage3EpisodeAirColumnPin> column_roots;
    uint256 pin_commitment{};
};

struct RCStage3EpisodeExtractHashExecution {
    stage3_hash_semantic::FlatBoundaryProofBundle proofs;
    RCStage3EpisodeHashSemanticBinding binding;
};

/**
 * One exact Extract tile. `input` is the flat V1 opening of its 32 signed
 * accumulator cells; recursion may replace these explicit words later.
 * `candidate_positions` is bound to the sampler POS column and determines the
 * repeated input word used by each rejection-sampler row.
 */
struct RCStage3EpisodeExtractTileProduct {
    uint64_t global_tile{0};
    uint32_t layer_ordinal{0};
    uint64_t layer_tile_index{0};
    std::array<int64_t, kRCMxBlockLen> input{};
    std::vector<uint8_t> candidate_positions;
    RCStage3EpisodeExtractMixPin mix_pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> mix_proof;
    RCStage3EpisodeAirPublicPin sampler_pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> sampler_proof;
    stage3_hash_air::ChaChaConsumptionManifest chacha_manifest;
    RCStage3EpisodeExtractHashExecution chacha;
    stage3_hash_air::ShaManifest scale_manifest;
    RCStage3EpisodeExtractHashExecution scale;
    uint256 tile_receipt_commitment{};
};

struct RCStage3EpisodeExtractProduct {
    uint16_t version{kRCStage3EpisodeExtractProductVersion};
    uint256 statement_commitment{};
    uint256 manifest_commitment{};
    uint64_t expected_tiles{0};
    std::vector<RCStage3EpisodeExtractTileProduct> tiles;
    /** When true, per-tile hash bundles are replaced by the two canonical
     * all-tile vertical bundles below. Manifests and semantic-memory bindings
     * remain per tile and retain identical endpoint semantics. */
    bool vertical_hash_proofs{false};
    stage3_hash_semantic::VerticalBoundaryProofBundle
        vertical_chacha;
    stage3_hash_semantic::VerticalBoundaryProofBundle
        vertical_scale;
    uint256 collection_commitment{};
};

/**
 * Honest bounded all-tile prover for endpoints 10--22.
 *
 * `inputs` is the canonical manifest tile order. The prover derives every
 * sampler witness, ChaCha/scale manifest, output byte, stream-memory shard and
 * tile-tree node. It updates only the five Extract-owned binding roots in
 * `manifest`; operand/GEMM/CTL roots remain caller-owned. The resulting
 * Extract and tile-stream products are self-verified before return.
 */
[[nodiscard]] bool ProveRCStage3EpisodeExtractAndTileStreamProducts(
    const RCStage3SuccinctProof& statement,
    RCStage3GemmExtractManifest& manifest,
    const std::vector<std::array<int64_t, kRCMxBlockLen>>& inputs,
    RCStage3EpisodeExtractProduct& extract,
    RCStage3EpisodeTileStreamProduct& tile_stream,
    std::string* why = nullptr);

/** Same exact tile/manifests/sampler semantics, with all ChaCha and all scale
 * boundaries proved in canonical 63-active vertical chunks. */
[[nodiscard]] bool
ProveRCStage3EpisodeExtractAndTileStreamProductsVertical(
    const RCStage3SuccinctProof& statement,
    RCStage3GemmExtractManifest& manifest,
    const std::vector<std::array<int64_t, kRCMxBlockLen>>& inputs,
    RCStage3EpisodeExtractProduct& extract,
    RCStage3EpisodeTileStreamProduct& tile_stream,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeRCStage3EpisodeExtractMixPinCommitment(
    const RCStage3EpisodeExtractMixPin& pin);
[[nodiscard]] uint256 ComputeRCStage3EpisodeExtractMixSeed(
    const RCStage3EpisodeExtractMixPin& pin);
[[nodiscard]] bool BuildRCStage3EpisodeExtractMixConstraintSystem(
    const RCStage3EpisodeExtractMixPin& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);
/** Role-explicit form used by the coupled product. The role is included in
 * the canonical ProgramTable commitment and only EpisodeExtract or
 * CoupledExtract is accepted. */
[[nodiscard]] bool BuildRCStage3ExtractMixConstraintSystemForRole(
    RCStage3RelationRole role,
    const RCStage3EpisodeExtractMixPin& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3EpisodeExtractMixProof(
    const RCStage3EpisodeExtractMixPin& pin,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeRCStage3EpisodeExtractInputTileRoot(
    const std::array<int64_t, kRCMxBlockLen>& input);
[[nodiscard]] uint256 ComputeRCStage3EpisodeExtractInputLayerRoot(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<uint256>& ordered_tile_input_roots);
[[nodiscard]] uint256 ComputeRCStage3EpisodeExtractScaleLayerRoot(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<uint256>& ordered_scale_manifest_commitments);
[[nodiscard]] uint256 ComputeRCStage3EpisodeExtractRecursiveLayerRoot(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<uint256>& ordered_tile_receipts);
[[nodiscard]] uint256 ComputeRCStage3EpisodeExtractTileReceiptCommitment(
    const RCStage3EpisodeExtractTileProduct& tile);
[[nodiscard]] uint256 ComputeRCStage3EpisodeExtractCollectionCommitment(
    const RCStage3EpisodeExtractProduct& product);

/** No proof execution and no native SHA/ChaCha/Extract replay. */
[[nodiscard]] bool ValidateRCStage3EpisodeExtractSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& product,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    std::string* why = nullptr);

/** Execute every mix, sampler, ChaCha, scale and downstream tile-stream proof. */
[[nodiscard]] bool VerifyRCStage3EpisodeExtractProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& product,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    std::string* why = nullptr);

struct RCStage3EpisodeExtractProductAudit {
    bool exact_all_tile_schedule{false};
    bool input_opening_and_mix_air_executed{false};
    bool sampler_walk_executed{false};
    bool chacha_consumption_air_executed{false};
    bool scale_sha_air_executed{false};
    bool dequant_output_root_bound{false};
    bool endpoint19_equality_executed{false};
    bool endpoints_10_through_14_locally_complete{false};
    bool gemm_output_producer_transitively_complete{false};
    bool recursively_consumed{false};
    bool transitively_complete{false};
    std::string remaining;
};

[[nodiscard]] RCStage3EpisodeExtractProductAudit
CurrentRCStage3EpisodeExtractProductAudit();

inline constexpr bool
    kRCStage3EpisodeExtractLocalRelationExecutable = true;
inline constexpr bool
    kRCStage3EpisodeExtractTransitivelyComplete = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_EXTRACT_PRODUCT_H
