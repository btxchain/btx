// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_EXTRACT_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_EXTRACT_PRODUCT_H

#include <matmul/matmul_v4_rc_stage3_episode_extract_product.h>
#include <matmul/matmul_v4_rc_stage3_extract_barrier_link.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3CoupledExtractProductVersion = 1;
inline constexpr uint64_t kRCStage3CoupledExtractMaxTiles = 1U << 16;

struct RCStage3CoupledExtractScheduleEntry {
    uint64_t instance{0};
    uint32_t barrier{0};
    uint32_t tile{0};
    uint256 extract_prf{};

    bool operator==(const RCStage3CoupledExtractScheduleEntry&) const =
        default;
};

struct RCStage3CoupledExtractHashExecution {
    stage3_hash_air::ChaChaConsumptionManifest chacha_manifest;
    stage3_hash_semantic::FlatBoundaryProofBundle chacha_proofs;
    RCStage3CoupledHashSemanticPin chacha_pin;
    stage3_hash_air::ShaManifest scale_manifest;
    stage3_hash_semantic::FlatBoundaryProofBundle scale_proofs;
};

struct RCStage3CoupledExtractTileProduct {
    RCStage3CoupledExtractScheduleEntry schedule;
    std::array<int64_t, kRCMxBlockLen> input{};
    std::array<int8_t, kRCMxBlockLen> output{};
    std::vector<uint8_t> candidate_positions;
    RCStage3EpisodeExtractMixPin mix_pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> mix_proof;
    RCStage3CoupledExtractHashExecution hashes;
    uint256 tile_commitment{};
};

struct RCStage3CoupledExtractProduct {
    uint16_t version{kRCStage3CoupledExtractProductVersion};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint64_t expected_tiles{0};
    std::vector<RCStage3CoupledExtractTileProduct> tiles;
    RCStage3CoupledSemanticFlatBundle input_cells;
    RCStage3CoupledSemanticFlatBundle sampler_cells;
    RCStage3CoupledSemanticFlatBundle scale_cells;
    RCStage3ExtractBarrierLinkExecution output_to_barrier;
    uint256 input_endpoint_root{};
    uint256 sampler_endpoint_root{};
    uint256 chacha_endpoint_root{};
    uint256 scale_endpoint_root{};
    uint256 output_endpoint_root{};
    uint256 product_commitment{};
};

[[nodiscard]] std::vector<RCStage3CoupledExtractScheduleEntry>
BuildRCStage3CoupledExtractSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeRCStage3CoupledExtractTileCommitment(
    const RCStage3CoupledExtractTileProduct& tile);
[[nodiscard]] uint256 ComputeRCStage3CoupledExtractProductCommitment(
    const RCStage3CoupledExtractProduct& product);

/** Deterministic structural builder; fills roots/manifests but not proofs. */
[[nodiscard]] bool BuildRCStage3CoupledExtractProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<std::array<int64_t, kRCMxBlockLen>>& inputs,
    RCStage3CoupledExtractProduct& out,
    std::string* why = nullptr);

/** Exact bounded prover helper over every shape-derived barrier/tile. */
[[nodiscard]] bool ProveRCStage3CoupledExtractProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<std::array<int64_t, kRCMxBlockLen>>& inputs,
    RCStage3CoupledExtractProduct& out,
    std::string* why = nullptr);

/** Schedule/root validation only; no native Extract/hash acceptance. */
[[nodiscard]] bool ValidateRCStage3CoupledExtractProductSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExtractProduct& product,
    std::string* why = nullptr);

/** Execute endpoints 42..46 and the ordered signed-byte equality into 47. */
[[nodiscard]] bool VerifyRCStage3CoupledExtractProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledExtractProduct& product,
    std::string* why = nullptr);

struct RCStage3CoupledExtractProductAudit {
    bool exact_all_tile_schedule{false};
    bool int64_mix_binding_executable{false};
    bool sampler_walk_executable{false};
    bool chacha_consumption_executable{false};
    bool scale_sha_executable{false};
    bool output_memory_root_executable{false};
    bool endpoint47_equality_executable{false};
    bool endpoints_42_through_46_bounded_complete{false};
    bool upstream_producer_provenance_complete{false};
    bool production_streaming_complete{false};
    bool recursively_consumed{false};
    bool transitively_complete{false};
    std::string remaining;
};

[[nodiscard]] RCStage3CoupledExtractProductAudit
CurrentRCStage3CoupledExtractProductAudit();

inline constexpr bool kRCStage3CoupledExtractBoundedExecutable = true;
inline constexpr bool kRCStage3CoupledExtractProductionStreaming = false;
inline constexpr bool kRCStage3CoupledExtractRecursivelyConsumed = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_EXTRACT_PRODUCT_H
