// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_merkle_multiproof.h>

#include <algorithm>
#include <cmath>
#include <limits>

namespace matmul::v4::rc::stage3_merkle_multiproof {
namespace {

void SetError(std::string* error, const char* message)
{
    if (error != nullptr) {
        *error = message;
    }
}

bool IsPowerOfTwo(uint64_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

uint32_t Log2PowerOfTwo(uint64_t value)
{
    uint32_t out = 0;
    while (value > 1) {
        value >>= 1;
        ++out;
    }
    return out;
}

uint64_t CheckedProduct(uint64_t a, uint64_t b, bool& ok)
{
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) {
        ok = false;
        return 0;
    }
    return a * b;
}

bool PositionLess(
    const MerkleNodePosition& a,
    const MerkleNodePosition& b)
{
    if (a.level != b.level) return a.level < b.level;
    return a.index < b.index;
}

} // namespace

bool BuildCanonicalMerkleMultiproofPlan(
    uint64_t leaf_count,
    const std::vector<uint64_t>& query_indices,
    CanonicalMerkleMultiproofPlan& out,
    std::string* error)
{
    out = {};
    if (!IsPowerOfTwo(leaf_count)) {
        SetError(error, "leaf count is not a nonzero power of two");
        return false;
    }
    if (query_indices.empty()) {
        SetError(error, "query set is empty");
        return false;
    }
    if (query_indices.size() > MAX_CANONICAL_MULTIPROOF_QUERIES) {
        SetError(error, "query count exceeds canonical protocol bound");
        return false;
    }
    if (std::any_of(
            query_indices.begin(),
            query_indices.end(),
            [leaf_count](uint64_t index) { return index >= leaf_count; })) {
        SetError(error, "query index is outside the Merkle domain");
        return false;
    }

    CanonicalMerkleMultiproofPlan plan;
    plan.leaf_count = leaf_count;
    plan.depth = Log2PowerOfTwo(leaf_count);
    plan.query_indices = query_indices;
    plan.unique_leaf_indices = query_indices;
    std::sort(
        plan.unique_leaf_indices.begin(),
        plan.unique_leaf_indices.end());
    plan.unique_leaf_indices.erase(
        std::unique(
            plan.unique_leaf_indices.begin(),
            plan.unique_leaf_indices.end()),
        plan.unique_leaf_indices.end());

    plan.query_to_unique_leaf.reserve(query_indices.size());
    for (const uint64_t query : query_indices) {
        const auto it = std::lower_bound(
            plan.unique_leaf_indices.begin(),
            plan.unique_leaf_indices.end(),
            query);
        plan.query_to_unique_leaf.push_back(
            static_cast<uint32_t>(
                std::distance(plan.unique_leaf_indices.begin(), it)));
    }

    bool product_ok = true;
    plan.naive_path_hashes = CheckedProduct(
        static_cast<uint64_t>(query_indices.size()),
        plan.depth,
        product_ok);
    if (!product_ok) {
        SetError(error, "naive path count overflows");
        return false;
    }

    std::vector<uint64_t> current = plan.unique_leaf_indices;
    for (uint32_t level = 0; level < plan.depth; ++level) {
        std::vector<uint64_t> parents;
        parents.reserve(current.size());
        for (const uint64_t index : current) {
            const uint64_t sibling = index ^ 1U;
            if (!std::binary_search(
                    current.begin(), current.end(), sibling)) {
                plan.frontier.push_back({level, sibling});
            }
            const uint64_t parent = index >> 1;
            if (parents.empty() || parents.back() != parent) {
                parents.push_back(parent);
                plan.internal_nodes.push_back({level + 1, parent});
            }
        }
        current = std::move(parents);
    }

    std::sort(
        plan.frontier.begin(), plan.frontier.end(), PositionLess);
    plan.complete_to_root =
        current.size() == 1 && current.front() == 0 &&
        !plan.internal_nodes.empty() &&
        plan.internal_nodes.back() ==
            MerkleNodePosition{plan.depth, 0};
    if (plan.depth == 0) {
        plan.complete_to_root =
            plan.unique_leaf_indices.size() == 1 &&
            plan.unique_leaf_indices.front() == 0 &&
            plan.internal_nodes.empty() &&
            plan.frontier.empty();
    }
    if (!plan.complete_to_root) {
        SetError(error, "canonical plan does not close to one root");
        return false;
    }

    out = std::move(plan);
    if (error != nullptr) error->clear();
    return true;
}

bool VerifyCanonicalMerkleMultiproofPlan(
    const CanonicalMerkleMultiproofPlan& plan,
    uint64_t expected_leaf_count,
    const std::vector<uint64_t>& expected_query_indices,
    std::string* error)
{
    CanonicalMerkleMultiproofPlan expected;
    std::string build_error;
    if (!BuildCanonicalMerkleMultiproofPlan(
            expected_leaf_count,
            expected_query_indices,
            expected,
            &build_error)) {
        if (error != nullptr) *error = build_error;
        return false;
    }
    if (!(plan == expected)) {
        SetError(error, "multiproof plan is not the canonical reconstruction");
        return false;
    }
    if (error != nullptr) error->clear();
    return true;
}

RowLeafSpongeCost AssessRowLeafSpongeCost(uint32_t row_width)
{
    // LeafHashRow absorbs c0,c1,c2 for every Fp3 plus the row index. Its
    // injective 10* padding always appends one field element, then zeros to a
    // rate-8 multiple. Every permutation updates all four capacity lanes.
    constexpr uint64_t RATE = 8;
    constexpr uint64_t CAPACITY = 4;
    constexpr uint64_t SBOXES_PER_PERMUTATION = 118;
    RowLeafSpongeCost out;
    out.row_width = row_width;
    out.message_field_elements =
        uint64_t{3} * row_width + 1;
    const uint64_t with_marker =
        out.message_field_elements + 1;
    out.permutations =
        (with_marker + RATE - 1) / RATE;
    out.padded_field_elements =
        out.permutations * RATE;
    out.padding_field_elements =
        out.padded_field_elements -
        out.message_field_elements;
    out.rate_lane_rounds =
        out.permutations * RATE;
    out.capacity_lane_rounds =
        out.permutations * CAPACITY;
    out.sbox_evaluations =
        out.permutations * SBOXES_PER_PERMUTATION;
    out.mandatory_padding_block_counted =
        out.padding_field_elements >= 1 &&
        (out.message_field_elements % RATE != 0 ||
         out.padding_field_elements == RATE);
    out.valid =
        row_width != 0 &&
        out.permutations != 0 &&
        out.padded_field_elements % RATE == 0 &&
        out.padding_field_elements >= 1 &&
        out.padding_field_elements <= RATE &&
        out.mandatory_padding_block_counted;
    return out;
}

RowLeafSpongeComparison AssessRowLeafSpongeComparison(
    uint32_t aggregate_width,
    const std::array<uint32_t, 3>& rap_group_widths,
    double q192_three_opening_baseline_ms,
    uint32_t baseline_queries,
    uint32_t rap_lanes,
    uint32_t rap_queries_per_lane)
{
    RowLeafSpongeComparison out;
    out.aggregate_width = aggregate_width;
    out.rap_group_widths = rap_group_widths;
    out.baseline_queries = baseline_queries;
    out.rap_lanes = rap_lanes;
    out.rap_queries_per_lane = rap_queries_per_lane;
    if (rap_lanes != 0 &&
        rap_queries_per_lane <=
            std::numeric_limits<uint32_t>::max() / rap_lanes) {
        out.rap_total_queries =
            rap_lanes * rap_queries_per_lane;
    }

    if (aggregate_width ==
            std::numeric_limits<uint32_t>::max()) {
        return out;
    }
    out.baseline_batch_row =
        AssessRowLeafSpongeCost(aggregate_width + 1);
    out.baseline_trace_row =
        AssessRowLeafSpongeCost(aggregate_width);
    for (size_t i = 0; i < rap_group_widths.size(); ++i) {
        out.rap_group_rows[i] =
            AssessRowLeafSpongeCost(rap_group_widths[i]);
    }

    out.width_partition_exact =
        aggregate_width != 0 &&
        rap_group_widths[0] != 0 &&
        rap_group_widths[1] != 0 &&
        rap_group_widths[2] == 1 &&
        uint64_t{rap_group_widths[0]} +
                rap_group_widths[1] ==
            aggregate_width;
    if (!out.width_partition_exact ||
        baseline_queries == 0 ||
        baseline_queries >
            MAX_CANONICAL_MULTIPROOF_QUERIES ||
        rap_lanes != 2 ||
        rap_queries_per_lane == 0 ||
        out.rap_total_queries >
            MAX_CANONICAL_MULTIPROOF_QUERIES) {
        return out;
    }

    out.baseline_permutations_per_query =
        2 * out.baseline_batch_row.permutations +
        out.baseline_trace_row.permutations;
    out.baseline_permutations_total =
        out.baseline_permutations_per_query *
        baseline_queries;
    out.baseline_padding_fields_total =
        (2 * out.baseline_batch_row.padding_field_elements +
         out.baseline_trace_row.padding_field_elements) *
        baseline_queries;
    out.baseline_capacity_lane_rounds_total =
        (2 * out.baseline_batch_row.capacity_lane_rounds +
         out.baseline_trace_row.capacity_lane_rounds) *
        baseline_queries;
    out.baseline_sbox_evaluations_total =
        (2 * out.baseline_batch_row.sbox_evaluations +
         out.baseline_trace_row.sbox_evaluations) *
        baseline_queries;

    // R0 and Rdep have current+next rows. Rq has only the quotient's current
    // row. Keeping these terms explicit prevents either next openings or the
    // per-segment padding blocks from disappearing in aggregate-width math.
    out.rap_permutations_per_query =
        2 * (out.rap_group_rows[0].permutations +
             out.rap_group_rows[1].permutations) +
        out.rap_group_rows[2].permutations;
    out.rap_permutations_total =
        out.rap_permutations_per_query *
        out.rap_total_queries;
    out.rap_padding_fields_total =
        (2 * (out.rap_group_rows[0].padding_field_elements +
              out.rap_group_rows[1].padding_field_elements) +
         out.rap_group_rows[2].padding_field_elements) *
        out.rap_total_queries;
    out.rap_capacity_lane_rounds_total =
        (2 * (out.rap_group_rows[0].capacity_lane_rounds +
              out.rap_group_rows[1].capacity_lane_rounds) +
         out.rap_group_rows[2].capacity_lane_rounds) *
        out.rap_total_queries;
    out.rap_sbox_evaluations_total =
        (2 * (out.rap_group_rows[0].sbox_evaluations +
              out.rap_group_rows[1].sbox_evaluations) +
         out.rap_group_rows[2].sbox_evaluations) *
        out.rap_total_queries;

    out.both_lanes_counted =
        out.rap_total_queries ==
            uint64_t{rap_lanes} * rap_queries_per_lane;
    out.mandatory_padding_counted =
        out.baseline_batch_row.mandatory_padding_block_counted &&
        out.baseline_trace_row.mandatory_padding_block_counted &&
        std::all_of(
            out.rap_group_rows.begin(),
            out.rap_group_rows.end(),
            [](const RowLeafSpongeCost& cost) {
                return
                    cost.valid &&
                    cost.mandatory_padding_block_counted;
            }) &&
        out.baseline_padding_fields_total != 0 &&
        out.rap_padding_fields_total != 0;
    out.capacity_rounds_counted =
        out.baseline_capacity_lane_rounds_total ==
            4 * out.baseline_permutations_total &&
        out.rap_capacity_lane_rounds_total ==
            4 * out.rap_permutations_total;
    if (out.baseline_permutations_total != 0) {
        out.calibrated_sponge_only_ms =
            q192_three_opening_baseline_ms *
            static_cast<double>(out.rap_permutations_total) /
            static_cast<double>(
                out.baseline_permutations_total);
    }

    // The 576.496 ms input is a whole-verifier observation, not an isolated
    // row-sponge measurement. Applying its ratio is calibration only.
    out.backend_partition_enforced = false;
    out.calibration_is_measurement = false;
    out.production_measurement_available = false;
    return out;
}

Q136ThreeRootMultiproofAssessment AssessQ136ThreeRootMultiproof(
    uint64_t leaf_count,
    const std::vector<uint64_t>& lane0_query_indices,
    const std::vector<uint64_t>& lane1_query_indices,
    double q192_three_opening_baseline_ms,
    double target_ms,
    uint32_t next_row_step,
    uint32_t aggregate_width,
    std::array<uint32_t, 3> rap_group_widths)
{
    Q136ThreeRootMultiproofAssessment out;
    out.leaf_count = leaf_count;
    out.q192_three_opening_baseline_ms =
        q192_three_opening_baseline_ms;
    out.target_ms = target_ms;
    out.next_row_step = next_row_step;
    out.aggregate_width = aggregate_width;
    out.rap_group_widths = rap_group_widths;
    out.row_leaf_sponge = AssessRowLeafSpongeComparison(
        aggregate_width,
        rap_group_widths,
        q192_three_opening_baseline_ms);
    if (lane0_query_indices.size() >
            MAX_CANONICAL_MULTIPROOF_QUERIES ||
        lane1_query_indices.size() >
            MAX_CANONICAL_MULTIPROOF_QUERIES ||
        lane1_query_indices.size() >
            MAX_CANONICAL_MULTIPROOF_QUERIES -
                lane0_query_indices.size()) {
        return out;
    }
    out.lane_queries = static_cast<uint32_t>(
        std::max(
            lane0_query_indices.size(),
            lane1_query_indices.size()));
    out.total_queries = static_cast<uint32_t>(
        lane0_query_indices.size() + lane1_query_indices.size());

    std::vector<uint64_t> queries;
    queries.reserve(out.total_queries);
    queries.insert(
        queries.end(),
        lane0_query_indices.begin(),
        lane0_query_indices.end());
    queries.insert(
        queries.end(),
        lane1_query_indices.begin(),
        lane1_query_indices.end());

    CanonicalMerkleMultiproofPlan current_plan;
    out.plan_valid = BuildCanonicalMerkleMultiproofPlan(
        leaf_count, queries, current_plan, nullptr);
    if (!out.plan_valid || out.total_queries == 0) return out;

    std::vector<uint64_t> current_next_queries = queries;
    current_next_queries.reserve(2 * queries.size());
    for (const uint64_t query : queries) {
        current_next_queries.push_back(
            (query + static_cast<uint64_t>(next_row_step)) &
            (leaf_count - 1));
    }
    CanonicalMerkleMultiproofPlan current_next_plan;
    out.plan_valid = BuildCanonicalMerkleMultiproofPlan(
        leaf_count,
        current_next_queries,
        current_next_plan,
        nullptr);
    if (!out.plan_valid) return out;

    out.depth = current_plan.depth;
    out.naive_hashes_per_root =
        current_plan.naive_path_hashes;
    out.exact_hashes_per_root =
        current_plan.internal_nodes.size();
    out.naive_current_next_hashes_per_root =
        current_next_plan.naive_path_hashes;
    out.exact_current_next_hashes_per_root =
        current_next_plan.internal_nodes.size();

    const uint64_t unique_query_bound = std::min<uint64_t>(
        out.total_queries, leaf_count);
    for (uint32_t level = 0; level < out.depth; ++level) {
        const uint64_t parent_slots =
            leaf_count >> (level + 1);
        out.worst_case_hashes_per_root +=
            std::min(unique_query_bound, parent_slots);
        const double slots = static_cast<double>(parent_slots);
        out.expected_hashes_per_root +=
            slots *
            (1.0 -
             std::pow(
                 1.0 - 1.0 / slots,
                 static_cast<double>(out.total_queries)));

        out.worst_case_current_next_hashes_per_root +=
            std::min<uint64_t>(
                2 * unique_query_bound, parent_slots);
        const uint64_t block_size =
            leaf_count / parent_slots;
        const uint64_t circular_step = std::min<uint64_t>(
            next_row_step % leaf_count,
            leaf_count -
                (next_row_step % leaf_count));
        const uint64_t union_size = std::min<uint64_t>(
            leaf_count,
            block_size +
                std::min(block_size, circular_step));
        out.expected_current_next_hashes_per_root +=
            slots *
            (1.0 -
             std::pow(
                 1.0 -
                     static_cast<double>(union_size) /
                         static_cast<double>(leaf_count),
                 static_cast<double>(out.total_queries)));
    }

    out.baseline_path_hashes =
        uint64_t{3} * 192 * out.depth;
    out.naive_target_path_hashes =
        2 * out.naive_current_next_hashes_per_root +
        out.naive_hashes_per_root;
    out.exact_target_path_hashes =
        2 * out.exact_current_next_hashes_per_root +
        out.exact_hashes_per_root;
    out.expected_target_path_hashes =
        2 * out.expected_current_next_hashes_per_root +
        out.expected_hashes_per_root;
    out.worst_case_target_path_hashes =
        2 * out.worst_case_current_next_hashes_per_root +
        out.worst_case_hashes_per_root;

    out.calibration_shape_exact =
        leaf_count == (uint64_t{1} << 24) &&
        lane0_query_indices.size() == 136 &&
        lane1_query_indices.size() == 136 &&
        aggregate_width == 1092 &&
        out.row_leaf_sponge.width_partition_exact &&
        out.row_leaf_sponge.both_lanes_counted;
    if (!out.calibration_shape_exact) return out;

    const double query_scale =
        static_cast<double>(out.total_queries) / 192.0;
    out.query_linear_model_ms =
        q192_three_opening_baseline_ms * query_scale;
    out.limb_volume_model_ms =
        out.row_leaf_sponge.calibrated_sponge_only_ms;
    const auto scale_path_time = [&out](double hashes) {
        return out.baseline_path_hashes == 0
            ? 0.0
            : out.q192_three_opening_baseline_ms * hashes /
                static_cast<double>(out.baseline_path_hashes);
    };
    out.exact_path_model_ms = scale_path_time(
        static_cast<double>(out.exact_target_path_hashes));
    out.expected_path_model_ms =
        scale_path_time(out.expected_target_path_hashes);
    out.worst_case_path_model_ms = scale_path_time(
        static_cast<double>(out.worst_case_target_path_hashes));
    out.expected_component_ceiling_ms = std::max(
        {out.query_linear_model_ms,
         out.limb_volume_model_ms,
         out.expected_path_model_ms});
    out.worst_case_component_ceiling_ms = std::max(
        {out.query_linear_model_ms,
         out.limb_volume_model_ms,
         out.worst_case_path_model_ms});
    out.expected_modeled_headroom_ms =
        target_ms - out.expected_component_ceiling_ms;
    out.worst_case_modeled_headroom_ms =
        target_ms - out.worst_case_component_ceiling_ms;
    out.expected_components_under_target =
        out.expected_component_ceiling_ms < target_ms;
    out.structural_worst_case_under_target =
        out.worst_case_component_ceiling_ms < target_ms;

    // A structural planner and a timing model are not a benchmark or proof.
    out.production_measurement_available = false;
    out.authority_ready = false;
    return out;
}

} // namespace matmul::v4::rc::stage3_merkle_multiproof
