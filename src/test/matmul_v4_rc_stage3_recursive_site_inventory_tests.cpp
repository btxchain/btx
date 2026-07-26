// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_recursive_site_inventory.h>

#include <limits>
#include <string>

namespace inv = matmul::v4::rc::recursive_site_inventory;
namespace sched = matmul::v4::rc::aggregation_scheduler;
namespace sites = matmul::v4::rc::soundness_scenarios;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_recursive_site_inventory_tests)

BOOST_AUTO_TEST_CASE(
    immutable_manifests_derive_exact_cap_and_fail_closed_residual)
{
    const auto manifest = sites::BuildProductionProofSiteManifest(
        sites::SelectedProductionProofSitePolicy());
    BOOST_REQUIRE(!manifest.commitment.IsNull());
    const auto schedule =
        sched::BuildProductionAggregationSchedule(manifest);
    BOOST_REQUIRE(!schedule.commitment.IsNull());

    inv::ProductionRecursiveSiteInventory inventory;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        inv::EnforceProductionRecursiveSiteHardCap(
            manifest,
            schedule,
            inv::kRecursiveSiteProtocolHardCap,
            &inventory,
            &why),
        why);
    BOOST_CHECK(inventory.checked_arithmetic);
    BOOST_CHECK(inventory.every_required_family_enumerated);
    BOOST_CHECK(
        inventory.family_ranges_match_immutable_schedule);
    BOOST_CHECK(inventory.hard_cap_check_executed);
    BOOST_CHECK(
        inventory.enumerated_schedule_within_hard_cap);
    BOOST_CHECK(
        inventory.hard_cap_enforced_for_enumerated_schedule);
    BOOST_CHECK_EQUAL(inventory.required_family_count, 28U);
    BOOST_CHECK_EQUAL(inventory.enumerated_family_count, 28U);
    BOOST_CHECK_EQUAL(inventory.families.size(), 28U);
    BOOST_CHECK_EQUAL(inventory.known_local_family_count, 1U);
    BOOST_CHECK_EQUAL(
        inventory.missing_all_instance_family_count, 11U);
    BOOST_CHECK_EQUAL(
        inventory.missing_hash_xof_family_count, 16U);
    BOOST_CHECK_EQUAL(
        inventory.enumerated_relation_leaf_sites,
        manifest.relation_leaf_sites);
    BOOST_CHECK_EQUAL(
        inventory.below_root_aggregation_sites,
        manifest.below_root_aggregation_sites);
    BOOST_CHECK_EQUAL(
        inventory.final_tree_aggregation_sites,
        manifest.final_tree_aggregation_sites);
    BOOST_CHECK_EQUAL(
        inventory.missing_rap_parent_sites,
        manifest.below_root_aggregation_sites +
            manifest.final_tree_aggregation_sites);
    BOOST_CHECK_EQUAL(
        inventory.enumerated_total_sites,
        manifest.total_proof_sites);
    BOOST_CHECK_EQUAL(
        inventory.authority_residual_sites,
        manifest.total_proof_sites);
    BOOST_CHECK_EQUAL(
        inventory.normalized_recursive_consumed_sites, 0U);
    BOOST_CHECK_EQUAL(
        inventory.known_local_leaf_sites, 331400U);
    BOOST_CHECK_EQUAL(
        inventory.known_local_leaf_sites +
            inventory.missing_all_instance_leaf_sites +
            inventory.missing_hash_xof_leaf_sites,
        inventory.enumerated_relation_leaf_sites);
    BOOST_CHECK(
        !inventory.every_leaf_relation_complete);
    BOOST_CHECK(
        !inventory.normalized_recursive_consumption_complete);
    BOOST_CHECK(!inventory.global_cap_enforced);
    BOOST_CHECK(!inventory.commitment.IsNull());
    BOOST_TEST_MESSAGE(
        "STAGE3_RECURSIVE_SITE_INVENTORY"
        << " total=" << inventory.enumerated_total_sites
        << " hard_cap=" << inventory.hard_cap
        << " known_local=" << inventory.known_local_leaf_sites
        << " missing_all_instance="
        << inventory.missing_all_instance_leaf_sites
        << " missing_hash_xof="
        << inventory.missing_hash_xof_leaf_sites
        << " missing_rap="
        << inventory.missing_rap_parent_sites
        << " authority_residual="
        << inventory.authority_residual_sites
        << " global_cap_enforced="
        << inventory.global_cap_enforced);
}

BOOST_AUTO_TEST_CASE(
    omission_overflow_substitution_and_over_cap_are_rejected)
{
    const auto manifest = sites::BuildProductionProofSiteManifest(
        sites::SelectedProductionProofSitePolicy());
    const auto schedule =
        sched::BuildProductionAggregationSchedule(manifest);
    BOOST_REQUIRE(!manifest.commitment.IsNull());
    BOOST_REQUIRE(!schedule.commitment.IsNull());
    std::string why;

    auto omitted = schedule;
    omitted.families.pop_back();
    BOOST_CHECK(
        !inv::EnforceProductionRecursiveSiteHardCap(
            manifest,
            omitted,
            inv::kRecursiveSiteProtocolHardCap,
            nullptr,
            &why));

    auto overflowed = manifest;
    overflowed.entries[0].logical_units =
        std::numeric_limits<uint64_t>::max();
    overflowed.entries[0].proof_sites =
        std::numeric_limits<uint64_t>::max();
    BOOST_CHECK(
        !inv::EnforceProductionRecursiveSiteHardCap(
            overflowed,
            schedule,
            inv::kRecursiveSiteProtocolHardCap,
            nullptr,
            &why));

    auto substituted = schedule;
    ++substituted.families[0].leaf_count;
    BOOST_CHECK(
        !inv::EnforceProductionRecursiveSiteHardCap(
            manifest,
            substituted,
            inv::kRecursiveSiteProtocolHardCap,
            nullptr,
            &why));

    inv::ProductionRecursiveSiteInventory over_cap;
    BOOST_CHECK(
        !inv::EnforceProductionRecursiveSiteHardCap(
            manifest,
            schedule,
            manifest.total_proof_sites - 1,
            &over_cap,
            &why));
    BOOST_CHECK(over_cap.checked_arithmetic);
    BOOST_CHECK(
        !over_cap.enumerated_schedule_within_hard_cap);
    BOOST_CHECK(
        !over_cap.hard_cap_enforced_for_enumerated_schedule);
    BOOST_CHECK(
        why.find("over_hard_cap") != std::string::npos);

    inv::ProductionRecursiveSiteInventory exact_cap;
    BOOST_REQUIRE(
        inv::EnforceProductionRecursiveSiteHardCap(
            manifest,
            schedule,
            manifest.total_proof_sites,
            &exact_cap,
            &why));
    BOOST_CHECK(
        exact_cap.hard_cap_enforced_for_enumerated_schedule);
    BOOST_CHECK(!exact_cap.global_cap_enforced);

    auto mutated_inventory = exact_cap;
    ++mutated_inventory.hard_cap;
    BOOST_CHECK(
        !inv::ValidateProductionRecursiveSiteInventory(
            manifest,
            schedule,
            mutated_inventory,
            &why));
}

BOOST_AUTO_TEST_SUITE_END()
