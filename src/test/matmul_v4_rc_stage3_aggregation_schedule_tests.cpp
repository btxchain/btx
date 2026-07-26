// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_aggregation_schedule.h>

#include <algorithm>
#include <cstdint>
#include <string>

namespace rc = matmul::v4::rc;
namespace scheduler =
    matmul::v4::rc::aggregation_scheduler;
namespace ss =
    matmul::v4::rc::soundness_scenarios;

namespace {

uint256 Filled(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

uint256 ParentCommitment(
    const scheduler::ParentWorkItem& work)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_TEST_PARENT";
    hash << work.seed;
    hash << work.parent_site;
    return hash.GetHash();
}

scheduler::ParentReceipt Receipt(
    const scheduler::ParentWorkItem& work)
{
    scheduler::ParentReceipt out;
    out.work_seed = work.seed;
    out.parent_commitment = ParentCommitment(work);
    out.binding =
        scheduler::CommitProductionAggregationReceipt(
            work, out.parent_commitment);
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_aggregation_schedule_tests)

BOOST_AUTO_TEST_CASE(
    exact_manifest_ranges_and_every_arity4_parent_are_recomputed)
{
    const auto manifest = ss::BuildProductionProofSiteManifest(
        ss::SelectedProductionProofSitePolicy());
    BOOST_REQUIRE(!manifest.commitment.IsNull());
    const auto schedule =
        scheduler::BuildProductionAggregationSchedule(manifest);
    BOOST_REQUIRE(!schedule.commitment.IsNull());
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        scheduler::ValidateProductionAggregationSchedule(
            manifest, schedule, &why),
        why);

    BOOST_CHECK_EQUAL(schedule.arity, 4U);
    BOOST_CHECK_EQUAL(schedule.families.size(), 28U);
    BOOST_CHECK_EQUAL(schedule.roles.size(), 14U);
    BOOST_CHECK_EQUAL(
        schedule.relation_leaf_sites,
        manifest.relation_leaf_sites);
    BOOST_CHECK_EQUAL(
        schedule.below_root_parent_sites,
        manifest.below_root_aggregation_sites);
    BOOST_CHECK_EQUAL(
        schedule.final_tree_parent_sites,
        manifest.final_tree_aggregation_sites);
    BOOST_CHECK_EQUAL(
        schedule.total_proof_sites,
        manifest.total_proof_sites);

    uint64_t leaf_cursor{0};
    for (size_t i = 0; i < schedule.families.size(); ++i) {
        const auto& range = schedule.families[i];
        BOOST_CHECK_EQUAL(range.family_index, i);
        BOOST_CHECK(range.kind == manifest.entries[i].kind);
        BOOST_CHECK(range.role == manifest.entries[i].role);
        BOOST_CHECK_EQUAL(range.first_leaf_site, leaf_cursor);
        BOOST_CHECK_EQUAL(
            range.leaf_count,
            manifest.entries[i].proof_sites);
        leaf_cursor += range.leaf_count;
    }
    BOOST_CHECK_EQUAL(leaf_cursor, manifest.relation_leaf_sites);

    uint64_t ordinal{0};
    uint64_t parent_site_cursor = manifest.relation_leaf_sites;
    for (const auto& role : schedule.roles) {
        uint64_t expected_child_first = role.first_leaf_site;
        uint64_t expected_child_count = role.leaf_count;
        for (const auto& level : role.levels) {
            BOOST_CHECK_EQUAL(
                level.first_child_site, expected_child_first);
            BOOST_CHECK_EQUAL(
                level.child_count, expected_child_count);
            BOOST_CHECK_EQUAL(
                level.first_parent_site, parent_site_cursor);
            BOOST_CHECK_EQUAL(
                level.parent_count,
                (level.child_count + 3) / 4);

            const auto first =
                scheduler::ProductionAggregationParentWorkItem(
                    schedule, Filled(1), ordinal, &why);
            BOOST_REQUIRE_MESSAGE(first.has_value(), why);
            BOOST_CHECK_EQUAL(
                first->parent_site, level.first_parent_site);
            BOOST_CHECK_EQUAL(first->first_child_site,
                              level.first_child_site);

            const uint64_t last_ordinal =
                ordinal + level.parent_count - 1;
            const auto last =
                scheduler::ProductionAggregationParentWorkItem(
                    schedule, Filled(1), last_ordinal, &why);
            BOOST_REQUIRE_MESSAGE(last.has_value(), why);
            BOOST_CHECK_EQUAL(
                last->parent_site,
                level.first_parent_site +
                    level.parent_count - 1);
            BOOST_CHECK_GE(last->child_count, 1U);
            BOOST_CHECK_LE(last->child_count, 4U);

            ordinal += level.parent_count;
            parent_site_cursor += level.parent_count;
            expected_child_first = level.first_parent_site;
            expected_child_count = level.parent_count;
        }
        BOOST_CHECK_EQUAL(expected_child_count, 1U);
        BOOST_CHECK_EQUAL(role.root_site, expected_child_first);
    }
    BOOST_CHECK_EQUAL(
        ordinal, manifest.below_root_aggregation_sites);
    BOOST_CHECK_EQUAL(
        parent_site_cursor,
        manifest.relation_leaf_sites +
            manifest.below_root_aggregation_sites);
    BOOST_CHECK(
        !scheduler::ProductionAggregationParentWorkItem(
             schedule, Filled(1), ordinal, &why)
             .has_value());
}

BOOST_AUTO_TEST_CASE(
    omission_reorder_duplicate_count_and_arity_are_rejected)
{
    const auto manifest = ss::BuildProductionProofSiteManifest(
        ss::SelectedProductionProofSitePolicy());
    const auto canonical =
        scheduler::BuildProductionAggregationSchedule(manifest);
    BOOST_REQUIRE(!canonical.commitment.IsNull());
    std::string why;

    auto omitted = canonical;
    omitted.families.pop_back();
    omitted.commitment =
        scheduler::CommitProductionAggregationSchedule(omitted);
    BOOST_CHECK(
        !scheduler::ValidateProductionAggregationSchedule(
            manifest, omitted, &why));

    auto reordered = canonical;
    std::swap(reordered.families[0], reordered.families[1]);
    reordered.commitment =
        scheduler::CommitProductionAggregationSchedule(reordered);
    BOOST_CHECK(
        !scheduler::ValidateProductionAggregationSchedule(
            manifest, reordered, &why));

    auto duplicated = canonical;
    duplicated.families[1] = duplicated.families[0];
    duplicated.commitment =
        scheduler::CommitProductionAggregationSchedule(duplicated);
    BOOST_CHECK(
        !scheduler::ValidateProductionAggregationSchedule(
            manifest, duplicated, &why));

    auto bad_count = canonical;
    --bad_count.families[0].leaf_count;
    bad_count.commitment =
        scheduler::CommitProductionAggregationSchedule(bad_count);
    BOOST_CHECK(
        !scheduler::ValidateProductionAggregationSchedule(
            manifest, bad_count, &why));

    auto bad_parent_count = canonical;
    BOOST_REQUIRE(!bad_parent_count.roles[0].levels.empty());
    --bad_parent_count.roles[0].levels[0].parent_count;
    bad_parent_count.commitment =
        scheduler::CommitProductionAggregationSchedule(
            bad_parent_count);
    BOOST_CHECK(
        !scheduler::ValidateProductionAggregationSchedule(
            manifest, bad_parent_count, &why));

    auto bad_arity = canonical;
    bad_arity.arity = 2;
    bad_arity.commitment =
        scheduler::CommitProductionAggregationSchedule(bad_arity);
    BOOST_CHECK(bad_arity.commitment.IsNull());
    BOOST_CHECK(
        !scheduler::ValidateProductionAggregationSchedule(
            manifest, bad_arity, &why));
}

BOOST_AUTO_TEST_CASE(
    binary_v1_schedule_is_exact_full_wide_eligible_and_soundness_screened)
{
    const auto manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const auto arity4 =
        scheduler::BuildProductionAggregationSchedule(manifest);
    const auto binary =
        scheduler::BuildBinaryV1AggregationSchedule(manifest);
    BOOST_REQUIRE(!binary.commitment.IsNull());
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        scheduler::ValidateBinaryV1AggregationSchedule(
            manifest, binary, &why),
        why);
    BOOST_CHECK_EQUAL(binary.arity, 2U);
    BOOST_CHECK_EQUAL(binary.families.size(), 28U);
    BOOST_CHECK_EQUAL(binary.roles.size(), 14U);
    BOOST_CHECK_EQUAL(
        binary.relation_leaf_sites,
        manifest.relation_leaf_sites);
    BOOST_CHECK_GT(
        binary.below_root_parent_sites,
        arity4.below_root_parent_sites);
    BOOST_CHECK_EQUAL(
        binary.total_proof_sites,
        binary.relation_leaf_sites +
            binary.below_root_parent_sites +
            binary.final_tree_parent_sites);

    uint64_t ordinal = 0;
    for (const auto& role : binary.roles) {
        for (const auto& level : role.levels) {
            BOOST_CHECK_EQUAL(
                level.parent_count,
                (level.child_count + 1) / 2);
            const auto first =
                scheduler::BinaryV1AggregationParentWorkItem(
                    binary, Filled(77), ordinal, &why);
            BOOST_REQUIRE_MESSAGE(first.has_value(), why);
            BOOST_CHECK_GE(first->child_count, 1U);
            BOOST_CHECK_LE(first->child_count, 2U);
            const auto last =
                scheduler::BinaryV1AggregationParentWorkItem(
                    binary, Filled(77),
                    ordinal + level.parent_count - 1,
                    &why);
            BOOST_REQUIRE_MESSAGE(last.has_value(), why);
            BOOST_CHECK_GE(last->child_count, 1U);
            BOOST_CHECK_LE(last->child_count, 2U);
            ordinal += level.parent_count;
        }
    }
    BOOST_CHECK_EQUAL(
        ordinal, binary.below_root_parent_sites);

    const auto scenario =
        scheduler::AssessBinaryV1SoundnessScenario(manifest);
    BOOST_CHECK_EQUAL(
        scenario.exact_total_sites,
        binary.total_proof_sites);
    BOOST_CHECK_GE(
        scenario.union_bound_cap,
        scenario.exact_total_sites);
    BOOST_CHECK(
        (scenario.union_bound_cap &
         (scenario.union_bound_cap - 1)) == 0);
    BOOST_CHECK(
        scenario.every_parent_child_count_at_most_two);
    BOOST_CHECK(!scenario.every_parent_full_wide_eligible);
    BOOST_CHECK(
        scenario.numeric_exact_site_target_met);
    BOOST_CHECK(scenario.numeric_cap_target_met);
    BOOST_CHECK(!scenario.all_node_execution_complete);
    BOOST_CHECK(!scenario.theorem_complete);
    BOOST_CHECK(!scenario.authority_eligible);

    auto bad = binary;
    bad.roles[0].levels[0].parent_count--;
    bad.commitment =
        scheduler::CommitBinaryV1AggregationSchedule(bad);
    BOOST_CHECK(
        !scheduler::ValidateBinaryV1AggregationSchedule(
            manifest, bad, &why));

    BOOST_TEST_MESSAGE(
        "binary-v1 recursive scenario: leaves="
        << binary.relation_leaf_sites
        << " parents=" << binary.below_root_parent_sites
        << " exact_sites=" << scenario.exact_total_sites
        << " cap=2^" << scenario.union_bound_log2
        << " exact_bits="
        << scenario.exact_site_screen.all_query_work_bits
        << " cap_bits="
        << scenario.cap_screen.all_query_work_bits);
}

BOOST_AUTO_TEST_CASE(
    streaming_receipts_are_ordered_and_root_replay_fails)
{
    const auto manifest = ss::BuildProductionProofSiteManifest(
        ss::SelectedProductionProofSitePolicy());
    const auto schedule =
        scheduler::BuildProductionAggregationSchedule(manifest);
    BOOST_REQUIRE(!schedule.commitment.IsNull());
    const uint256 root_a = Filled(101);
    const uint256 root_b = Filled(102);
    std::string why;

    uint64_t expected_ordinal{0};
    auto cursor_a =
        scheduler::BeginProductionAggregationExecution(
            schedule, root_a);
    const auto honest =
        [&](const scheduler::ParentWorkItem& work,
            std::string*) -> std::optional<
                scheduler::ParentReceipt> {
        BOOST_CHECK_EQUAL(
            work.parent_ordinal, expected_ordinal++);
        return Receipt(work);
    };
    BOOST_REQUIRE_MESSAGE(
        scheduler::ExecuteProductionAggregationPage(
            manifest, schedule, honest, 7, cursor_a, &why),
        why);
    BOOST_CHECK_EQUAL(cursor_a.next_parent_ordinal, 7U);
    BOOST_CHECK(!cursor_a.complete);

    const auto work_a =
        scheduler::ProductionAggregationParentWorkItem(
            schedule, root_a, 0, &why);
    const auto work_b =
        scheduler::ProductionAggregationParentWorkItem(
            schedule, root_b, 0, &why);
    BOOST_REQUIRE(work_a.has_value());
    BOOST_REQUIRE(work_b.has_value());
    BOOST_CHECK(work_a->seed != work_b->seed);
    const scheduler::ParentReceipt replayed = Receipt(*work_a);

    auto cursor_b =
        scheduler::BeginProductionAggregationExecution(
            schedule, root_b);
    const auto replay_callback =
        [&](const scheduler::ParentWorkItem&,
            std::string*) -> std::optional<
                scheduler::ParentReceipt> {
        return replayed;
    };
    BOOST_CHECK(
        !scheduler::ExecuteProductionAggregationPage(
            manifest, schedule, replay_callback, 1,
            cursor_b, &why));
    BOOST_CHECK_EQUAL(cursor_b.next_parent_ordinal, 0U);

    auto duplicate_cursor =
        scheduler::BeginProductionAggregationExecution(
            schedule, root_a);
    const scheduler::ParentReceipt first = Receipt(*work_a);
    const auto duplicate_callback =
        [&](const scheduler::ParentWorkItem&,
            std::string*) -> std::optional<
                scheduler::ParentReceipt> {
        return first;
    };
    BOOST_CHECK(
        !scheduler::ExecuteProductionAggregationPage(
            manifest, schedule, duplicate_callback, 2,
            duplicate_cursor, &why));
    BOOST_CHECK_EQUAL(
        duplicate_cursor.next_parent_ordinal, 1U);

    auto omitted_cursor =
        scheduler::BeginProductionAggregationExecution(
            schedule, root_a);
    omitted_cursor.next_parent_ordinal = 1;
    BOOST_CHECK(
        !scheduler::ExecuteProductionAggregationPage(
            manifest, schedule, honest, 1, omitted_cursor, &why));
}

BOOST_AUTO_TEST_CASE(structural_scheduler_does_not_claim_child_proofs)
{
    BOOST_CHECK(
        scheduler::
            kProductionAggregationStructuralSchedulerExecutable);
    BOOST_CHECK(
        !scheduler::
            kProductionAggregationCryptographicChildConsumptionReady);
}

BOOST_AUTO_TEST_SUITE_END()
