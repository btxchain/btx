// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_WIRING_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_WIRING_PRODUCT_H

#include <matmul/matmul_v4_rc_stage3_episode_gemm_product.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3EpisodeWiringProductVersion = 1;

struct RCStage3EpisodeWiringAirPin {
    uint16_t version{kRCStage3EpisodeWiringProductVersion};
    RCStage3RelationEndpoint endpoint{};
    uint256 statement_commitment{};
    uint256 manifest_commitment{};
    uint32_t schedule_index{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint256 challenge_seed{};
    std::vector<RCStage3EpisodeAirColumnPin> column_roots;
    uint256 pin_commitment{};
};

struct RCStage3EpisodeWiringTransposeSchedule {
    uint32_t schedule_index{0};
    uint32_t layer_ordinal{0};
    RCStage3EpisodeWiringOperandSlot slot{
        RCStage3EpisodeWiringOperandSlot::B};
    uint32_t first_column{0};
    uint32_t n_chunks{0};
    uint32_t source_rows{0};
    uint32_t source_cols{0};
    uint64_t value_count{0};
    uint256 registered_source_root{};

    bool operator==(
        const RCStage3EpisodeWiringTransposeSchedule&) const = default;
};

struct RCStage3EpisodeWiringTransposeEdge {
    RCStage3EpisodeWiringTransposeSchedule schedule;
    RCStage3EpisodeWiringAirPin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> proof;
    RCStage3EpisodeSemanticMemoryBundle source_memory;
    RCStage3EpisodeSemanticMemoryBundle destination_memory;
    uint256 transposed_vector_root{};
    uint256 edge_commitment{};
};

struct RCStage3EpisodeWiringResidualSchedule {
    uint32_t schedule_index{0};
    uint32_t layer_ordinal{0};
    uint32_t residual_first_column{0};
    uint32_t residual_n_chunks{0};
    uint64_t value_count{0};
    uint256 registered_y_root{};
    uint256 registered_residual_root{};

    bool operator==(
        const RCStage3EpisodeWiringResidualSchedule&) const = default;
};

struct RCStage3EpisodeWiringResidualEdge {
    RCStage3EpisodeWiringResidualSchedule schedule;
    RCStage3EpisodeWiringAirPin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> proof;
    RCStage3EpisodeSemanticMemoryBundle y_memory;
    RCStage3EpisodeSemanticMemoryBundle residual_memory;
    RCStage3EpisodeSemanticMemoryBundle extract_input_memory;
    uint256 edge_commitment{};
};

struct RCStage3EpisodeWiringRoundOrderSchedule {
    uint32_t schedule_index{0};
    uint32_t producer_layer_ordinal{0};
    uint32_t consumer_layer_ordinal{0};
    uint32_t round_index{0};
    uint32_t first_column{0};
    uint32_t n_chunks{0};
    uint64_t value_count{0};
    uint256 registered_consumer_root{};

    bool operator==(
        const RCStage3EpisodeWiringRoundOrderSchedule&) const = default;
};

struct RCStage3EpisodeWiringRoundOrderEdge {
    RCStage3EpisodeWiringRoundOrderSchedule schedule;
    RCStage3EpisodeWiringAirPin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> proof;
    RCStage3EpisodeSemanticMemoryBundle producer_memory;
    RCStage3EpisodeSemanticMemoryBundle consumer_memory;
    uint256 edge_commitment{};
};

struct RCStage3EpisodeWiringProduct {
    uint16_t version{kRCStage3EpisodeWiringProductVersion};
    uint256 statement_commitment{};
    uint256 manifest_commitment{};
    uint256 gemm_product_commitment{};
    uint256 extract_product_commitment{};
    std::vector<RCStage3EpisodeWiringTransposeEdge> transpose_edges;
    std::vector<RCStage3EpisodeWiringResidualEdge> residual_edges;
    std::vector<RCStage3EpisodeWiringRoundOrderEdge> round_order_edges;
    uint256 product_commitment{};
};

[[nodiscard]] std::vector<RCStage3EpisodeWiringTransposeSchedule>
BuildRCStage3EpisodeWiringTransposeSchedule(
    const RCStage3GemmExtractManifest& manifest);
[[nodiscard]] std::vector<RCStage3EpisodeWiringResidualSchedule>
BuildRCStage3EpisodeWiringResidualSchedule(
    const RCStage3GemmExtractManifest& manifest);
[[nodiscard]] std::vector<RCStage3EpisodeWiringRoundOrderSchedule>
BuildRCStage3EpisodeWiringRoundOrderSchedule(
    const RCStage3GemmExtractManifest& manifest);

/**
 * Native transpose dual-LogUp AirConstraintSystem (the production builder,
 * with beta/gamma baked as closure constants). Exposed so the constraint-
 * bytecode migration can be DIFFERENTIALLY tested against the exact native
 * relation. Only pin.n_rows, pin.challenge_seed and pin.schedule_index are
 * consulted.
 */
[[nodiscard]] air_quotient::AirConstraintSystem<gkr_field::Fp3>
BuildRCStage3EpisodeWiringTransposeConstraintSystem(
    const RCStage3EpisodeWiringAirPin& pin);

/**
 * The four verifier-owned transpose challenges [beta0, gamma0, beta1, gamma1]
 * exactly as the native builder derives them, so the bytecode adapter can be
 * driven with the identical post-challenge column vector.
 */
[[nodiscard]] std::array<gkr_field::Fp3, 4>
RCStage3EpisodeWiringTransposeChallengeVector(
    const uint256& challenge_seed, uint32_t schedule_index);

[[nodiscard]] uint256 ComputeRCStage3EpisodeWiringAirPinCommitment(
    const RCStage3EpisodeWiringAirPin& pin);
[[nodiscard]] uint256 ComputeRCStage3EpisodeWiringProductCommitment(
    const RCStage3EpisodeWiringProduct& product);

/**
 * Build every bounded endpoint-16..18 AIR and proof-owned memory alias.
 * Parent products are treated as proof-owned inputs; their recursive/external
 * execution remains a separate transitive obligation.
 */
[[nodiscard]] bool BuildRCStage3EpisodeWiringProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const RCStage3EpisodeExtractProduct& extract,
    RCStage3EpisodeWiringProduct& out,
    std::string* why = nullptr);

/** Exact schedule/root validation without executing local quotient proofs. */
[[nodiscard]] bool ValidateRCStage3EpisodeWiringProductSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeWiringProduct& product,
    std::string* why = nullptr);

/** Execute every endpoint-16..18 AIR and semantic-memory proof. */
[[nodiscard]] bool VerifyRCStage3EpisodeWiringLocalProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeWiringProduct& product,
    std::string* why = nullptr);

struct RCStage3EpisodeWiringProductAudit {
    bool exact_lambda_transpose_schedule{false};
    bool dual_transpose_permutation_executable{false};
    bool transpose_memory_aliases_executable{false};
    bool exact_residual_schedule{false};
    bool residual_addition_executable{false};
    bool residual_memory_aliases_executable{false};
    bool exact_round_order_schedule{false};
    bool every_producer_consumer_edge_executable{false};
    bool round_order_memory_aliases_executable{false};
    bool endpoints_16_through_18_bounded_local_complete{false};
    bool external_producer_provenance_complete{false};
    bool production_streaming_complete{false};
    bool recursively_consumed{false};
    bool transitively_complete{false};
    std::string remaining;
};

[[nodiscard]] RCStage3EpisodeWiringProductAudit
CurrentRCStage3EpisodeWiringProductAudit();

inline constexpr bool
    kRCStage3EpisodeWiringBoundedLocalExecutable = true;
inline constexpr bool
    kRCStage3EpisodeWiringProductionStreamingComplete = false;
inline constexpr bool
    kRCStage3EpisodeWiringRecursivelyConsumed = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_WIRING_PRODUCT_H
