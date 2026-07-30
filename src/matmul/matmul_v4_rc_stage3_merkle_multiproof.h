// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MERKLE_MULTIPROOF_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MERKLE_MULTIPROOF_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_merkle_multiproof {

/**
 * Position of a node in a binary Merkle tree.  Leaves are at level zero and
 * the root is at level log2(leaf_count).
 */
struct MerkleNodePosition {
    uint32_t level{0};
    uint64_t index{0};

    bool operator==(const MerkleNodePosition&) const = default;
};

/**
 * Canonical structural plan for a shared Merkle multiproof.
 *
 * Hash values deliberately do not live here.  The proof codec must attach one
 * digest to each `frontier` position, in this exact order.  A verifier starts
 * with one opened digest for every `unique_leaf_indices` entry, consumes the
 * frontier, and hashes every `internal_nodes` position exactly once.
 *
 * `query_indices` preserves Fiat--Shamir order.  Duplicate query indices map
 * to one opened leaf through `query_to_unique_leaf`.
 */
struct CanonicalMerkleMultiproofPlan {
    uint64_t leaf_count{0};
    uint32_t depth{0};
    std::vector<uint64_t> query_indices;
    std::vector<uint64_t> unique_leaf_indices;
    std::vector<uint32_t> query_to_unique_leaf;
    std::vector<MerkleNodePosition> frontier;
    std::vector<MerkleNodePosition> internal_nodes;
    uint64_t naive_path_hashes{0};
    bool complete_to_root{false};

    bool operator==(const CanonicalMerkleMultiproofPlan&) const = default;
};

/** A protocol bound, not merely a memory-reservation hint. */
inline constexpr uint32_t MAX_CANONICAL_MULTIPROOF_QUERIES = 4096;

[[nodiscard]] bool BuildCanonicalMerkleMultiproofPlan(
    uint64_t leaf_count,
    const std::vector<uint64_t>& query_indices,
    CanonicalMerkleMultiproofPlan& out,
    std::string* error = nullptr);

/**
 * Rebuild the plan from verifier-owned dimensions and transcript queries.
 * Comparing against that reconstruction rejects omissions, duplicates,
 * reordering, out-of-range nodes, and a proof-supplied query schedule.
 */
[[nodiscard]] bool VerifyCanonicalMerkleMultiproofPlan(
    const CanonicalMerkleMultiproofPlan& plan,
    uint64_t expected_leaf_count,
    const std::vector<uint64_t>& expected_query_indices,
    std::string* error = nullptr);

/** Exact AlgHash row-leaf sponge accounting for one row of Fp3 values. */
struct RowLeafSpongeCost {
    uint32_t row_width{0};
    uint64_t message_field_elements{0};
    uint64_t padding_field_elements{0};
    uint64_t padded_field_elements{0};
    uint64_t permutations{0};
    uint64_t rate_lane_rounds{0};
    uint64_t capacity_lane_rounds{0};
    uint64_t sbox_evaluations{0};
    bool mandatory_padding_block_counted{false};
    bool valid{false};
};

[[nodiscard]] RowLeafSpongeCost
AssessRowLeafSpongeCost(uint32_t row_width);

/**
 * Exact current-vs-RAP row-leaf inventory.
 *
 * Current Q192:
 *   current batch row W+1, supplemental next row W+1, trace-binding row W.
 *
 * Ordered dual-Q136 RAP:
 *   current rows R0/Rdep/Rq, next rows R0/Rdep, with
 *   width(R0)+width(Rdep)=W and width(Rq)=1.
 */
struct RowLeafSpongeComparison {
    uint32_t aggregate_width{0};
    std::array<uint32_t, 3> rap_group_widths{};
    uint32_t baseline_queries{0};
    uint32_t rap_lanes{0};
    uint32_t rap_queries_per_lane{0};
    uint32_t rap_total_queries{0};

    RowLeafSpongeCost baseline_batch_row;
    RowLeafSpongeCost baseline_trace_row;
    std::array<RowLeafSpongeCost, 3> rap_group_rows{};

    uint64_t baseline_permutations_per_query{0};
    uint64_t baseline_permutations_total{0};
    uint64_t baseline_padding_fields_total{0};
    uint64_t baseline_capacity_lane_rounds_total{0};
    uint64_t baseline_sbox_evaluations_total{0};

    uint64_t rap_permutations_per_query{0};
    uint64_t rap_permutations_total{0};
    uint64_t rap_padding_fields_total{0};
    uint64_t rap_capacity_lane_rounds_total{0};
    uint64_t rap_sbox_evaluations_total{0};

    double calibrated_sponge_only_ms{0.0};
    bool width_partition_exact{false};
    bool both_lanes_counted{false};
    bool mandatory_padding_counted{false};
    bool capacity_rounds_counted{false};
    /** False until the normalized W=1092 adapter exports this exact split. */
    bool backend_partition_enforced{false};
    bool calibration_is_measurement{false};
    bool production_measurement_available{false};
};

[[nodiscard]] RowLeafSpongeComparison
AssessRowLeafSpongeComparison(
    uint32_t aggregate_width,
    const std::array<uint32_t, 3>& rap_group_widths,
    double q192_three_opening_baseline_ms = 576.496,
    uint32_t baseline_queries = 192,
    uint32_t rap_lanes = 2,
    uint32_t rap_queries_per_lane = 136);

struct Q136ThreeRootMultiproofAssessment {
    uint64_t leaf_count{0};
    uint32_t depth{0};
    uint32_t lane_queries{0};
    uint32_t total_queries{0};
    uint32_t next_row_step{0};
    uint32_t aggregate_width{0};
    std::array<uint32_t, 3> rap_group_widths{};
    RowLeafSpongeComparison row_leaf_sponge;

    uint64_t naive_hashes_per_root{0};
    uint64_t exact_hashes_per_root{0};
    double expected_hashes_per_root{0.0};
    uint64_t worst_case_hashes_per_root{0};
    uint64_t naive_current_next_hashes_per_root{0};
    uint64_t exact_current_next_hashes_per_root{0};
    double expected_current_next_hashes_per_root{0.0};
    uint64_t worst_case_current_next_hashes_per_root{0};
    uint64_t baseline_path_hashes{0};
    uint64_t naive_target_path_hashes{0};
    uint64_t exact_target_path_hashes{0};
    double expected_target_path_hashes{0.0};
    uint64_t worst_case_target_path_hashes{0};

    double q192_three_opening_baseline_ms{0.0};
    double query_linear_model_ms{0.0};
    double limb_volume_model_ms{0.0};
    double exact_path_model_ms{0.0};
    double expected_path_model_ms{0.0};
    double worst_case_path_model_ms{0.0};
    double expected_component_ceiling_ms{0.0};
    double worst_case_component_ceiling_ms{0.0};
    double target_ms{0.0};
    double expected_modeled_headroom_ms{0.0};
    double worst_case_modeled_headroom_ms{0.0};

    bool plan_valid{false};
    bool calibration_shape_exact{false};
    bool expected_components_under_target{false};
    bool structural_worst_case_under_target{false};
    bool production_measurement_available{false};
    bool authority_ready{false};
};

/**
 * Models the three ordered RAP roots R0/Rdep/Rq at transcript-derived query
 * indices. R0 and Rdep authenticate both current and next rows; Rq
 * authenticates the current quotient row. Thus there are five leaf openings
 * but only three roots. Current+next positions are planned together per root,
 * so their shared upper paths are deduplicated.
 *
 * The Q192 baseline already contains three full-width row openings per query
 * (batch current, supplemental next, and trace binding). The RAP construction
 * absorbs about 2W+1 values/query instead of 3W+2, but uses the five structural
 * paths above. The model exposes those components separately.
 *
 * Segment padding and capacity-lane work are counted exactly. The conversion
 * from those counts to wall time, remaining verifier work, and the final
 * verifier implementation remain unmeasured, so this is not a production
 * bound and cannot make the proof authoritative.
 */
[[nodiscard]] Q136ThreeRootMultiproofAssessment
AssessQ136ThreeRootMultiproof(
    uint64_t leaf_count,
    const std::vector<uint64_t>& lane0_query_indices,
    const std::vector<uint64_t>& lane1_query_indices,
    double q192_three_opening_baseline_ms = 576.496,
    double target_ms = 900.0,
    uint32_t next_row_step = 16,
    uint32_t aggregate_width = 1092,
    std::array<uint32_t, 3> rap_group_widths =
        {172, 920, 1});

} // namespace matmul::v4::rc::stage3_merkle_multiproof

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MERKLE_MULTIPROOF_H
