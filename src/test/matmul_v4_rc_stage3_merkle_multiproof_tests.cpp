// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_merkle_multiproof.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace mp = matmul::v4::rc::stage3_merkle_multiproof;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_merkle_multiproof_tests)

namespace {

std::vector<uint64_t> DeterministicQueries(
    uint64_t seed,
    uint32_t count,
    uint64_t mask)
{
    std::vector<uint64_t> out;
    out.reserve(count);
    uint64_t state = seed;
    for (uint32_t i = 0; i < count; ++i) {
        // SplitMix64 is used only to make a reproducible structural scenario.
        state += 0x9e3779b97f4a7c15ULL;
        uint64_t value = state;
        value = (value ^ (value >> 30)) *
            0xbf58476d1ce4e5b9ULL;
        value = (value ^ (value >> 27)) *
            0x94d049bb133111ebULL;
        value ^= value >> 31;
        out.push_back(value & mask);
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    row_leaf_sponge_counts_padding_capacity_and_both_q136_lanes)
{
    const mp::RowLeafSpongeCost full_padding =
        mp::AssessRowLeafSpongeCost(5);
    BOOST_REQUIRE(full_padding.valid);
    BOOST_CHECK_EQUAL(
        full_padding.message_field_elements, 16U);
    BOOST_CHECK_EQUAL(
        full_padding.padding_field_elements, 8U);
    BOOST_CHECK_EQUAL(full_padding.permutations, 3U);
    BOOST_CHECK_EQUAL(full_padding.rate_lane_rounds, 24U);
    BOOST_CHECK_EQUAL(
        full_padding.capacity_lane_rounds, 12U);
    BOOST_CHECK_EQUAL(full_padding.sbox_evaluations, 354U);
    BOOST_CHECK(
        full_padding.mandatory_padding_block_counted);

    const mp::RowLeafSpongeComparison balanced =
        mp::AssessRowLeafSpongeComparison(
            1092, {546, 546, 1});
    BOOST_REQUIRE(balanced.width_partition_exact);
    BOOST_CHECK(balanced.both_lanes_counted);
    BOOST_CHECK(balanced.mandatory_padding_counted);
    BOOST_CHECK(balanced.capacity_rounds_counted);
    BOOST_CHECK_EQUAL(
        balanced.baseline_batch_row.permutations, 411U);
    BOOST_CHECK_EQUAL(
        balanced.baseline_trace_row.permutations, 410U);
    BOOST_CHECK_EQUAL(
        balanced.baseline_permutations_per_query, 1232U);
    BOOST_CHECK_EQUAL(
        balanced.baseline_permutations_total, 236544U);
    BOOST_CHECK_EQUAL(
        balanced.baseline_padding_fields_total, 3648U);
    BOOST_CHECK_EQUAL(
        balanced.baseline_capacity_lane_rounds_total,
        946176U);
    BOOST_CHECK_EQUAL(
        balanced.baseline_sbox_evaluations_total,
        27912192U);
    BOOST_CHECK_EQUAL(
        balanced.rap_group_rows[0].permutations, 205U);
    BOOST_CHECK_EQUAL(
        balanced.rap_group_rows[1].permutations, 205U);
    BOOST_CHECK_EQUAL(
        balanced.rap_group_rows[2].permutations, 1U);
    BOOST_CHECK_EQUAL(
        balanced.rap_permutations_per_query, 821U);
    BOOST_CHECK_EQUAL(
        balanced.rap_total_queries, 272U);
    BOOST_CHECK_EQUAL(
        balanced.rap_permutations_total, 223312U);
    BOOST_CHECK_EQUAL(
        balanced.rap_padding_fields_total, 2176U);
    BOOST_CHECK_EQUAL(
        balanced.rap_capacity_lane_rounds_total, 893248U);
    BOOST_CHECK_EQUAL(
        balanced.rap_sbox_evaluations_total, 26350816U);
    BOOST_CHECK_CLOSE(
        balanced.calibrated_sponge_only_ms,
        544.2474751082251,
        1e-9);
    BOOST_CHECK(!balanced.calibration_is_measurement);
    BOOST_CHECK(!balanced.backend_partition_enforced);
    BOOST_CHECK(!balanced.production_measurement_available);

    // Segmenting can add padding blocks. They must be charged from the exact
    // widths, rather than by hashing one fictitious aggregate 2W+1 row.
    const mp::RowLeafSpongeComparison unbalanced =
        mp::AssessRowLeafSpongeComparison(
            1092, {1091, 1, 1});
    BOOST_REQUIRE(unbalanced.width_partition_exact);
    BOOST_CHECK_EQUAL(
        unbalanced.rap_permutations_per_query, 823U);
    BOOST_CHECK_EQUAL(
        unbalanced.rap_permutations_total, 223856U);
    BOOST_CHECK_EQUAL(
        unbalanced.rap_padding_fields_total, 6528U);
    BOOST_CHECK_EQUAL(
        unbalanced.rap_capacity_lane_rounds_total, 895424U);
    BOOST_CHECK_CLOSE(
        unbalanced.calibrated_sponge_only_ms,
        545.5732911255411,
        1e-9);

    // This is the mechanically consistent normalized projection of the
    // executable W=976 split (172,804,1). The W=1092 adapter itself remains
    // absent, so the planner must not call the partition backend-enforced.
    const mp::RowLeafSpongeComparison modeled_normalized =
        mp::AssessRowLeafSpongeComparison(
            1092, {172, 920, 1});
    BOOST_REQUIRE(modeled_normalized.width_partition_exact);
    BOOST_CHECK_EQUAL(
        modeled_normalized.rap_group_rows[0].permutations,
        65U);
    BOOST_CHECK_EQUAL(
        modeled_normalized.rap_group_rows[1].permutations,
        346U);
    BOOST_CHECK_EQUAL(
        modeled_normalized.rap_permutations_per_query,
        823U);
    BOOST_CHECK(!modeled_normalized.backend_partition_enforced);

    const mp::RowLeafSpongeComparison omitted_column =
        mp::AssessRowLeafSpongeComparison(
            1092, {546, 545, 1});
    BOOST_CHECK(!omitted_column.width_partition_exact);
    BOOST_CHECK_EQUAL(
        omitted_column.rap_permutations_total, 0U);
    const mp::RowLeafSpongeComparison omitted_lane =
        mp::AssessRowLeafSpongeComparison(
            1092, {546, 546, 1}, 576.496, 192, 1, 136);
    BOOST_CHECK(!omitted_lane.both_lanes_counted);
    BOOST_CHECK_EQUAL(
        omitted_lane.rap_permutations_total, 0U);
}

BOOST_AUTO_TEST_CASE(
    q136_two_lane_plan_is_canonical_bounded_and_closes_to_root)
{
    constexpr uint64_t N = uint64_t{1} << 24;
    const std::vector<uint64_t> lane0 =
        DeterministicQueries(0x7130d5902846a1bdULL, 136, N - 1);
    const std::vector<uint64_t> lane1 =
        DeterministicQueries(0xc8155b662a1028efULL, 136, N - 1);
    std::vector<uint64_t> queries = lane0;
    queries.insert(queries.end(), lane1.begin(), lane1.end());

    mp::CanonicalMerkleMultiproofPlan plan;
    std::string error;
    BOOST_REQUIRE(
        mp::BuildCanonicalMerkleMultiproofPlan(
            N, queries, plan, &error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(plan.depth, 24U);
    BOOST_CHECK_EQUAL(plan.query_indices.size(), 272U);
    BOOST_CHECK_EQUAL(plan.query_to_unique_leaf.size(), 272U);
    BOOST_CHECK_LE(plan.unique_leaf_indices.size(), 272U);
    BOOST_CHECK_EQUAL(plan.naive_path_hashes, 6528U);
    BOOST_CHECK(plan.complete_to_root);
    BOOST_REQUIRE(!plan.internal_nodes.empty());
    BOOST_CHECK((
        plan.internal_nodes.back() ==
        mp::MerkleNodePosition{24, 0}));
    BOOST_CHECK_LE(plan.internal_nodes.size(), 4591U);
    BOOST_CHECK(
        mp::VerifyCanonicalMerkleMultiproofPlan(
            plan, N, queries, &error));

    const mp::Q136ThreeRootMultiproofAssessment assessment =
        mp::AssessQ136ThreeRootMultiproof(
            N, lane0, lane1);
    BOOST_REQUIRE(assessment.plan_valid);
    BOOST_CHECK_EQUAL(assessment.total_queries, 272U);
    BOOST_CHECK_EQUAL(assessment.naive_hashes_per_root, 6528U);
    BOOST_CHECK_EQUAL(
        assessment.exact_hashes_per_root,
        plan.internal_nodes.size());
    BOOST_CHECK_EQUAL(
        assessment.exact_hashes_per_root, 4372U);
    BOOST_CHECK_CLOSE(
        assessment.expected_hashes_per_root,
        4357.84238409401,
        1e-9);
    BOOST_CHECK_EQUAL(
        assessment.worst_case_hashes_per_root, 4591U);
    BOOST_CHECK_EQUAL(
        assessment.naive_current_next_hashes_per_root,
        13056U);
    BOOST_CHECK_EQUAL(
        assessment.exact_current_next_hashes_per_root,
        5755U);
    BOOST_CHECK_CLOSE(
        assessment.expected_current_next_hashes_per_root,
        5716.763937986806,
        1e-9);
    BOOST_CHECK_EQUAL(
        assessment.worst_case_current_next_hashes_per_root,
        8639U);
    BOOST_CHECK_EQUAL(
        assessment.baseline_path_hashes, 13824U);
    BOOST_CHECK_EQUAL(
        assessment.naive_target_path_hashes, 32640U);
    BOOST_CHECK_EQUAL(
        assessment.exact_target_path_hashes, 15882U);
    BOOST_CHECK_CLOSE(
        assessment.expected_target_path_hashes,
        15791.370260067622,
        1e-9);
    BOOST_CHECK_EQUAL(
        assessment.worst_case_target_path_hashes, 21869U);
    BOOST_CHECK_CLOSE(
        assessment.query_linear_model_ms,
        816.7026666666667,
        1e-9);
    BOOST_CHECK_CLOSE(
        assessment.limb_volume_model_ms,
        545.5732911255411,
        1e-9);
    BOOST_CHECK_CLOSE(
        assessment.expected_path_model_ms,
        658.5403493524266,
        1e-9);
    BOOST_CHECK_CLOSE(
        assessment.exact_path_model_ms,
        662.3198402777778,
        1e-9);
    BOOST_CHECK_CLOSE(
        assessment.worst_case_path_model_ms,
        911.9929849537037,
        1e-9);
    BOOST_CHECK_CLOSE(
        assessment.expected_component_ceiling_ms,
        816.7026666666667,
        1e-9);
    BOOST_CHECK_CLOSE(
        assessment.expected_modeled_headroom_ms,
        83.29733333333331,
        1e-9);
    BOOST_CHECK_CLOSE(
        assessment.worst_case_modeled_headroom_ms,
        -11.9929849537037,
        1e-9);
    BOOST_CHECK(assessment.expected_components_under_target);
    BOOST_CHECK(!assessment.structural_worst_case_under_target);
    BOOST_CHECK(assessment.calibration_shape_exact);
    BOOST_CHECK(
        assessment.row_leaf_sponge.width_partition_exact);
    BOOST_CHECK(
        assessment.row_leaf_sponge.both_lanes_counted);
    BOOST_CHECK(
        assessment.row_leaf_sponge.mandatory_padding_counted);
    BOOST_CHECK(
        assessment.row_leaf_sponge.capacity_rounds_counted);
    BOOST_CHECK(
        !assessment.row_leaf_sponge.calibration_is_measurement);
    BOOST_CHECK(
        !assessment.row_leaf_sponge.backend_partition_enforced);
    BOOST_CHECK(!assessment.production_measurement_available);
    BOOST_CHECK(!assessment.authority_ready);
}

BOOST_AUTO_TEST_CASE(
    canonical_reconstruction_rejects_plan_and_schedule_mutations)
{
    constexpr uint64_t N = uint64_t{1} << 12;
    const std::vector<uint64_t> queries{
        1, 5, 9, 12, 12, 511, 2048, 4095};
    mp::CanonicalMerkleMultiproofPlan plan;
    BOOST_REQUIRE(
        mp::BuildCanonicalMerkleMultiproofPlan(
            N, queries, plan));

    const auto rejects = [&](mp::CanonicalMerkleMultiproofPlan mutated) {
        BOOST_CHECK(
            !mp::VerifyCanonicalMerkleMultiproofPlan(
                mutated, N, queries));
    };

    {
        auto mutated = plan;
        mutated.frontier.pop_back();
        rejects(std::move(mutated));
    }
    {
        auto mutated = plan;
        mutated.frontier.push_back(mutated.frontier.back());
        rejects(std::move(mutated));
    }
    {
        auto mutated = plan;
        mutated.frontier.front().index ^= 1U;
        rejects(std::move(mutated));
    }
    {
        auto mutated = plan;
        std::reverse(
            mutated.frontier.begin(), mutated.frontier.end());
        rejects(std::move(mutated));
    }
    {
        auto mutated = plan;
        mutated.internal_nodes.pop_back();
        rejects(std::move(mutated));
    }
    {
        auto mutated = plan;
        mutated.query_to_unique_leaf.front() ^= 1U;
        rejects(std::move(mutated));
    }
    {
        auto mutated = plan;
        mutated.query_indices.front() ^= 1U;
        rejects(std::move(mutated));
    }

    std::vector<uint64_t> reordered = queries;
    std::swap(reordered.front(), reordered.back());
    BOOST_CHECK(
        !mp::VerifyCanonicalMerkleMultiproofPlan(
            plan, N, reordered));

    mp::CanonicalMerkleMultiproofPlan invalid;
    BOOST_CHECK(
        !mp::BuildCanonicalMerkleMultiproofPlan(
            N - 1, queries, invalid));
    BOOST_CHECK(
        !mp::BuildCanonicalMerkleMultiproofPlan(
            N, std::vector<uint64_t>{N}, invalid));
    BOOST_CHECK(
        !mp::BuildCanonicalMerkleMultiproofPlan(
            N, {}, invalid));
    BOOST_CHECK(
        !mp::BuildCanonicalMerkleMultiproofPlan(
            uint64_t{1} << 24,
            std::vector<uint64_t>(
                mp::MAX_CANONICAL_MULTIPROOF_QUERIES + 1, 0),
            invalid));
}

BOOST_AUTO_TEST_SUITE_END()
