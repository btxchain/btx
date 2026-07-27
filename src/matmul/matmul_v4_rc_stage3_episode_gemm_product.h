// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_GEMM_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_GEMM_PRODUCT_H

#include <matmul/matmul_v4_rc_stage3_episode_extract_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_relation_product.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3EpisodeGemmProductVersion = 1;

enum RCStage3EpisodeGemmDotColumn : uint32_t {
    kRCStage3GemmDotActive = 0,
    kRCStage3GemmDotStart,
    kRCStage3GemmDotEnd,
    kRCStage3GemmDotA,
    kRCStage3GemmDotB,
    kRCStage3GemmDotY,
    kRCStage3GemmDotResidual,
    kRCStage3GemmDotExtractInput,
    kRCStage3GemmDotProduct,
    kRCStage3GemmDotAccumulatorBefore,
    kRCStage3GemmDotAccumulatorAfter,
    kRCStage3GemmDotColumns,
};

struct RCStage3EpisodeGemmDotPin {
    uint16_t version{kRCStage3EpisodeGemmProductVersion};
    uint256 statement_commitment{};
    uint256 manifest_commitment{};
    uint32_t layer_ordinal{0};
    uint64_t layer_tile_index{0};
    uint32_t contraction_size{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint32_t n_coeffs{0};
    std::vector<RCStage3EpisodeAirColumnPin> column_roots;
    uint256 pin_commitment{};
};

struct RCStage3EpisodeGemmTileProof {
    uint64_t layer_tile_index{0};
    RCStage3EpisodeGemmDotPin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> proof;
};

/**
 * Exact V1 flat openings for one Λ layer.
 *
 * A is m×k row-major. B is stored in its underlying committed order:
 * k×n when b.transpose=false, n×k otherwise. `gemm_y` is the pure m×n
 * product; `residual` is empty except fused DOWN and is added only at the
 * Extract-input boundary.
 */
struct RCStage3EpisodeGemmLayerProduct {
    uint32_t layer_ordinal{0};
    std::vector<int8_t> operand_a;
    std::vector<int8_t> operand_b;
    std::vector<int64_t> gemm_y;
    std::vector<int8_t> residual;
    std::vector<RCStage3EpisodeGemmTileProof> tiles;
    uint256 layer_receipt_commitment{};
};

struct RCStage3EpisodeGemmProduct {
    uint16_t version{kRCStage3EpisodeGemmProductVersion};
    uint256 statement_commitment{};
    uint256 manifest_commitment{};
    std::vector<RCStage3EpisodeGemmLayerProduct> layers;
    /** Executes every registered non-transposed A/B equality edge. */
    RCStage3EpisodeWiringCopyClosure wiring;
    uint256 collection_commitment{};
};

struct RCStage3EpisodeGemmLayerWitness {
    std::vector<int8_t> operand_a;
    std::vector<int8_t> operand_b;
    /** Required only for Λ layers with residual_first_column >= 0. */
    std::vector<int8_t> residual;
};

/**
 * Honest bounded all-layer/all-output-tile GEMM prover.
 *
 * The function computes every Y cell from A/B, requires Y+residual to equal
 * the already proved Extract input tiles, updates the three GEMM-owned
 * manifest roots, refreshes the dependent Extract/tile-stream manifest
 * commitments, proves every dot-product AIR, and proves the exact wiring-copy
 * closure. All three products are self-verified before return.
 */
[[nodiscard]] bool ProveRCStage3EpisodeGemmProduct(
    const RCStage3SuccinctProof& statement,
    RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3EpisodeGemmLayerWitness>& witnesses,
    RCStage3EpisodeExtractProduct& extract,
    RCStage3EpisodeTileStreamProduct& tile_stream,
    RCStage3EpisodeGemmProduct& out,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeRCStage3EpisodeGemmDotPinCommitment(
    const RCStage3EpisodeGemmDotPin& pin);
[[nodiscard]] uint256 ComputeRCStage3EpisodeGemmDotSeed(
    const RCStage3EpisodeGemmDotPin& pin);
[[nodiscard]] bool BuildRCStage3EpisodeGemmDotConstraintSystem(
    const RCStage3EpisodeGemmDotPin& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3EpisodeGemmDotProof(
    const RCStage3EpisodeGemmDotPin& pin,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeRCStage3EpisodeGemmLayerReceiptCommitment(
    const RCStage3EpisodeGemmLayerProduct& layer);
[[nodiscard]] uint256 ComputeRCStage3EpisodeGemmCollectionCommitment(
    const RCStage3EpisodeGemmProduct& product);

/**
 * Validate Λ coverage and every proof-owned opening/root alias. This performs
 * indexing and commitment computation only; it never multiplies matrices.
 */
[[nodiscard]] bool ValidateRCStage3EpisodeGemmSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& product,
    const RCStage3EpisodeExtractProduct& extract,
    std::string* why = nullptr);

/** Execute every dot-product AIR, Extract-input equality and wiring proof. */
[[nodiscard]] bool VerifyRCStage3EpisodeGemmProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& product,
    const RCStage3EpisodeExtractProduct& extract,
    std::string* why = nullptr);

struct RCStage3EpisodeGemmProductAudit {
    bool immutable_full_lambda_schedule{false};
    bool all_operand_openings_bound{false};
    bool every_dot_product_air_executed{false};
    bool complete_signed_arithmetic_identity{false};
    bool y_root_bound{false};
    bool y_residual_to_extract_input_equality{false};
    bool internal_extract_and_wiring_producers_linked{false};
    bool endpoints_5_through_8_locally_complete{false};
    bool external_builder_provenance_complete{false};
    bool production_streaming_complete{false};
    bool recursively_consumed{false};
    bool transitively_complete{false};
    std::string remaining;
};

[[nodiscard]] RCStage3EpisodeGemmProductAudit
CurrentRCStage3EpisodeGemmProductAudit();

inline constexpr bool kRCStage3EpisodeGemmLocalRelationExecutable = true;
inline constexpr bool kRCStage3EpisodeGemmTransitivelyComplete = false;

} // namespace matmul::v4::rc

#endif
