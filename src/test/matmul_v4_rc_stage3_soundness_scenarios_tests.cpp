// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_stage3_narrow_recurse.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <algorithm>
#include <cmath>
#include <limits>

namespace ss = matmul::v4::rc::soundness_scenarios;
namespace nr = matmul::v4::rc::narrow_recurse;
namespace rc = matmul::v4::rc;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_soundness_scenarios_tests)

BOOST_AUTO_TEST_CASE(profile2_site_inventory_is_exact_but_not_a_global_cap)
{
    const ss::ProductionSiteInventory inventory =
        ss::AssessProductionSiteInventory();
    BOOST_CHECK(inventory.profile2_layout_exact);
    BOOST_CHECK_EQUAL(inventory.gemm_layers, 400U);
    BOOST_CHECK_EQUAL(inventory.gemm_cells, 347'490'222'080ULL);
    BOOST_CHECK_EQUAL(inventory.extract_tiles, 10'859'069'440ULL);
    BOOST_CHECK_EQUAL(inventory.signed_range_shards, 331'400ULL);
    BOOST_CHECK_EQUAL(inventory.scale_schedule_shards, 10'472ULL);
    BOOST_CHECK_EQUAL(
        inventory.range_ctl_child_air_invocations, 662'800ULL);
    BOOST_CHECK_EQUAL(inventory.known_leaf_air_invocations, 994'200ULL);
    BOOST_CHECK(inventory.final_tree_manifest_exact);
    BOOST_CHECK_EQUAL(inventory.final_tree_sites, 29U);
    BOOST_CHECK_EQUAL(
        inventory.known_sites_including_final_tree, 994'229ULL);
    BOOST_CHECK_EQUAL(inventory.known_sites_log2_ceiling, 20U);
    BOOST_CHECK_EQUAL(
        inventory.declared_candidate_site_budget, 1ULL << 26);
    BOOST_CHECK_EQUAL(inventory.declared_candidate_site_log2, 26U);
    BOOST_CHECK(inventory.known_sites_fit_declared_budget);

    // The current solver's rejection loops are unbounded, so it has no finite
    // cap even though the proposed bounded policy has a complete count ledger.
    BOOST_CHECK_EQUAL(inventory.complete_global_site_upper_bound, 0U);
    BOOST_CHECK(
        !inventory.complete_global_upper_bound_manifest_derived);
    BOOST_CHECK_EQUAL(
        inventory.conditional_stage3_site_upper_bound,
        1ULL << inventory.conditional_stage3_site_log2);
    BOOST_CHECK_LE(
        inventory.conditional_stage3_site_upper_bound, 1ULL << 28);
    BOOST_CHECK_EQUAL(
        inventory.conditional_rejection_blocks_per_32_outputs, 4U);
    BOOST_CHECK(
        inventory.conditional_stage3_upper_bound_manifest_derived);
    BOOST_CHECK(
        !inventory.declared_budget_enforced_by_executable_backend);
}

BOOST_AUTO_TEST_CASE(fixed_q_dual_q96_screen_does_not_imply_all_q_security)
{
    const ss::FriScenario dual = ss::AssessFriScenario(
        "dual_q96", 2, 96, 3, 24,
        ss::BatchChallengeShape::SinglePower, 1ULL << 28);
    BOOST_REQUIRE(dual.parameters_valid);
    BOOST_CHECK_CLOSE(dual.batching_loss_bits, 13.9999119422, 1e-7);
    BOOST_CHECK_CLOSE(dual.proximity_rbr_bits, 87.6035672400, 1e-7);
    BOOST_CHECK_CLOSE(dual.fixed_query_work_bits, 107.207134480, 1e-7);
    BOOST_CHECK_CLOSE(dual.all_query_work_bits, 73.6035672400, 1e-7);
    BOOST_CHECK(!dual.numeric_target_met);
    BOOST_CHECK_EQUAL(dual.certified_bits, 0U);
    BOOST_CHECK(!dual.authority_eligible);
}

BOOST_AUTO_TEST_CASE(all_q_comparison_identifies_only_conditional_candidates)
{
    const std::vector<ss::FriScenario> scenarios =
        ss::AssessCanonicalFriScenarios();
    BOOST_REQUIRE_EQUAL(scenarios.size(), 10U);
    const auto find = [&](const char* name) -> const ss::FriScenario& {
        const auto it = std::find_if(
            scenarios.begin(), scenarios.end(),
            [&](const ss::FriScenario& value) {
                return value.name == name;
            });
        BOOST_REQUIRE(it != scenarios.end());
        return *it;
    };

    const auto& single24 =
        find("single_fp3_q192_lde24_independent");
    BOOST_CHECK_CLOSE(single24.all_query_work_bits, 100.93347803, 1e-6);
    BOOST_CHECK(single24.numeric_target_met);

    const auto& single23 =
        find("single_fp3_q192_lde23_independent");
    BOOST_CHECK_CLOSE(single23.all_query_work_bits, 102.93347781, 1e-6);
    BOOST_CHECK(single23.numeric_target_met);

    const auto& dual128 =
        find("dual_fp3_q128_lde24_independent");
    BOOST_CHECK_CLOSE(dual128.all_query_work_bits, 103.80475632, 1e-6);
    BOOST_CHECK(dual128.numeric_target_met);

    const auto& dual136 =
        find("dual_fp3_q136_lde24_independent");
    BOOST_CHECK_GT(dual136.all_query_work_bits, 111.1);
    BOOST_CHECK_LT(dual136.all_query_work_bits, 111.2);
    BOOST_CHECK(dual136.numeric_target_met);

    const auto& dual148 =
        find("dual_fp3_q148_lde24_independent");
    BOOST_CHECK_GT(dual148.all_query_work_bits, 113.9);
    BOOST_CHECK_LT(dual148.all_query_work_bits, 114.0);
    BOOST_CHECK(dual148.numeric_target_met);

    const auto& fp4 = find("single_fp4_q192_lde24_power");
    BOOST_CHECK_GT(fp4.all_query_work_bits, 114.2);
    BOOST_CHECK_LT(fp4.all_query_work_bits, 114.3);
    BOOST_CHECK(fp4.numeric_target_met);
    BOOST_CHECK(!fp4.field_backend_present);

    for (const auto& scenario : scenarios) {
        BOOST_CHECK(scenario.published_batching_factor_exact);
        BOOST_CHECK(!scenario.global_site_upper_bound_manifest_derived);
        BOOST_CHECK(!scenario.formal_reduction_complete);
        BOOST_CHECK_EQUAL(scenario.certified_bits, 0U);
        BOOST_CHECK(!scenario.authority_eligible);
    }
}

BOOST_AUTO_TEST_CASE(site_manifest_thresholds_are_visible_not_assumed)
{
    // With a hypothetical exact <=2^20 site manifest, single Fp3/LDE24 with
    // independent coefficients would have room.  The production inventory
    // intentionally does not claim that upper bound today.
    const ss::FriScenario conditional = ss::AssessFriScenario(
        "conditional_site_manifest", 1, 192, 3, 24,
        ss::BatchChallengeShape::IndependentCoefficients, 1ULL << 20);
    BOOST_REQUIRE(conditional.parameters_valid);
    BOOST_CHECK_GT(conditional.all_query_work_bits, 106.9);
    BOOST_CHECK_LT(conditional.all_query_work_bits, 107.0);
    BOOST_CHECK(conditional.numeric_target_met);
    BOOST_CHECK(!conditional.global_site_upper_bound_manifest_derived);
    BOOST_CHECK_EQUAL(conditional.certified_bits, 0U);
}

BOOST_AUTO_TEST_CASE(complete_site_manifest_requires_an_explicit_rejection_cap)
{
    ss::ProductionProofSitePolicy current;
    current.max_rejection_blocks_per_32_outputs = 0;
    const auto unbounded =
        ss::BuildProductionProofSiteManifest(current);
    BOOST_CHECK(unbounded.commitment.IsNull());
    BOOST_CHECK_EQUAL(unbounded.total_proof_sites, 0U);
    BOOST_CHECK(
        !unbounded.complete_global_upper_bound_manifest_derived);
    std::string why;
    BOOST_CHECK(!ss::ValidateProductionProofSiteManifest(
        unbounded, &why));
    BOOST_CHECK(
        why.find("no_finite_cap") != std::string::npos);

    const auto selected_policy =
        ss::SelectedProductionProofSitePolicy();
    BOOST_CHECK_EQUAL(
        selected_policy.max_rejection_blocks_per_32_outputs,
        rc::kRCStage3V1MaxRejectionBlocksPer32);
    BOOST_CHECK_EQUAL(selected_policy.hash_parallel_lanes, 4U);
    BOOST_CHECK_EQUAL(selected_policy.aggregation_arity, 4U);
    BOOST_CHECK_EQUAL(
        selected_policy.relation_rows_per_site, 1U << 18);
    const auto selected =
        ss::BuildProductionProofSiteManifest(selected_policy);
    BOOST_REQUIRE(!selected.commitment.IsNull());
    BOOST_REQUIRE_MESSAGE(
        ss::ValidateProductionProofSiteManifest(selected, &why), why);
    BOOST_CHECK_EQUAL(selected.entries.size(), 28U);
    BOOST_CHECK(selected.arithmetic_exact);
    BOOST_CHECK(selected.all_registered_roles_covered);
    BOOST_CHECK(selected.rejection_loops_bounded);
    BOOST_CHECK(selected.backend_shape_supported);
    BOOST_CHECK(selected.executable_hash_parallel_packing);
    BOOST_CHECK(
        selected.executable_rejection_paths_enforce_policy);
    BOOST_CHECK(
        !selected.recursive_scheduler_consumes_manifest);
    BOOST_CHECK(
        selected.complete_global_upper_bound_manifest_derived);
    BOOST_CHECK(!selected.executable_backend_enforces_policy);
    BOOST_CHECK_EQUAL(selected.relation_leaf_sites, 28'116'241ULL);
    BOOST_CHECK_EQUAL(
        selected.below_root_aggregation_sites, 9'372'141ULL);
    BOOST_CHECK_EQUAL(selected.total_proof_sites, 37'488'397ULL);
    BOOST_CHECK_GE(selected.total_proof_sites, 1ULL << 25);
    BOOST_CHECK_LE(selected.total_proof_sites, 1ULL << 28);
    BOOST_CHECK_GE(selected.union_bound_cap, selected.total_proof_sites);
    BOOST_CHECK_EQUAL(
        selected.union_bound_cap,
        1ULL << selected.union_bound_log2);

    const auto exact_hybrid = nr::AssessFriDualQ128HybridBound(
        selected.total_proof_sites,
        nr::FriDualCommitmentTopology::SharedMaster);
    BOOST_REQUIRE(exact_hybrid.parameters_valid);
    BOOST_CHECK_CLOSE(
        exact_hybrid.composed_union_bits, 102.0196358875, 1e-7);
    BOOST_CHECK(exact_hybrid.numerical_target_met);
    BOOST_CHECK(!exact_hybrid.exact_site_manifest_backend_enforced);
    BOOST_CHECK(!exact_hybrid.formal_reduction_complete);
    BOOST_CHECK(!exact_hybrid.authority_eligible);

    // Preserve the pre-packing conditional inventory as an explicit
    // comparison rather than silently rewriting its 100.4057-bit result.
    const auto unpacked = ss::BuildProductionProofSiteManifest(
        ss::UnpackedProductionProofSitePolicy());
    BOOST_REQUIRE(!unpacked.commitment.IsNull());
    BOOST_CHECK_EQUAL(
        unpacked.policy.hash_parallel_lanes, 1U);
    BOOST_CHECK_GT(unpacked.total_proof_sites, selected.total_proof_sites);
    const auto unpacked_hybrid = nr::AssessFriDualQ128HybridBound(
        unpacked.total_proof_sites,
        nr::FriDualCommitmentTopology::SharedMaster);
    BOOST_REQUIRE(unpacked_hybrid.parameters_valid);
    BOOST_CHECK_CLOSE(
        unpacked_hybrid.composed_union_bits, 100.4056957335, 1e-7);
    for (const auto& entry : selected.entries) {
        BOOST_TEST_MESSAGE(
            "stage3 site family kind="
            << static_cast<uint32_t>(entry.kind)
            << " role=" << static_cast<uint32_t>(entry.role)
            << " logical_units=" << entry.logical_units
            << " units_per_site=" << entry.units_per_site
            << " proof_sites=" << entry.proof_sites);
    }
    BOOST_TEST_MESSAGE(
        "selected Stage3 conditional site manifest: leaves="
        << selected.relation_leaf_sites
        << " recurse=" << selected.below_root_aggregation_sites
        << " total=" << selected.total_proof_sites
        << " cap=2^" << selected.union_bound_log2
        << " composed_shared_bits="
        << exact_hybrid.composed_union_bits);
}

BOOST_AUTO_TEST_CASE(site_manifest_rejects_omission_relabel_substitution_and_overflow)
{
    const auto canonical = ss::BuildProductionProofSiteManifest(
        ss::SelectedProductionProofSitePolicy());
    BOOST_REQUIRE(!canonical.commitment.IsNull());
    std::string why;

    auto omitted = canonical;
    omitted.entries.pop_back();
    BOOST_CHECK(!ss::ValidateProductionProofSiteManifest(
        omitted, &why));

    auto reordered = canonical;
    std::swap(reordered.entries[4], reordered.entries[5]);
    BOOST_CHECK(!ss::ValidateProductionProofSiteManifest(
        reordered, &why));

    auto relabelled = canonical;
    relabelled.entries[0].role =
        matmul::v4::rc::RCStage3RelationRole::EpisodeGemm;
    BOOST_CHECK(!ss::ValidateProductionProofSiteManifest(
        relabelled, &why));

    auto substituted_count = canonical;
    --substituted_count.entries[6].logical_units;
    BOOST_CHECK(!ss::ValidateProductionProofSiteManifest(
        substituted_count, &why));

    auto undercharged = canonical;
    --undercharged.entries[7].proof_sites;
    BOOST_CHECK(!ss::ValidateProductionProofSiteManifest(
        undercharged, &why));

    auto substituted_lane_count = canonical;
    substituted_lane_count.policy.hash_parallel_lanes = 1;
    BOOST_CHECK(!ss::ValidateProductionProofSiteManifest(
        substituted_lane_count, &why));

    auto substituted_commitment = canonical;
    substituted_commitment.commitment.SetNull();
    BOOST_CHECK(!ss::ValidateProductionProofSiteManifest(
        substituted_commitment, &why));

    auto overflowing = ss::SelectedProductionProofSitePolicy();
    overflowing.max_rejection_blocks_per_32_outputs =
        std::numeric_limits<uint32_t>::max();
    const auto overflow_manifest =
        ss::BuildProductionProofSiteManifest(overflowing);
    BOOST_CHECK(overflow_manifest.commitment.IsNull());

    auto too_wide = ss::SelectedProductionProofSitePolicy();
    too_wide.hash_parallel_lanes = 8;
    BOOST_CHECK(
        ss::BuildProductionProofSiteManifest(too_wide)
            .commitment.IsNull());
}

BOOST_AUTO_TEST_CASE(site_scenarios_choose_supported_quaternary_aggregation)
{
    const auto scenarios = ss::AssessProductionProofSiteScenarios();
    BOOST_REQUIRE_EQUAL(scenarios.size(), 8U);
    const auto find = [&](const char* name)
        -> const ss::ProductionProofSiteScenario& {
        const auto it = std::find_if(
            scenarios.begin(), scenarios.end(),
            [&](const auto& scenario) {
                return scenario.name == name;
            });
        BOOST_REQUIRE(it != scenarios.end());
        return *it;
    };
    const auto& unbounded = find("current_unbounded_binary");
    BOOST_CHECK(!unbounded.finite);
    BOOST_CHECK_EQUAL(unbounded.union_bound_cap, 0U);

    const auto& binary = find("bounded4_binary_unpacked");
    const auto& unpacked =
        find("bounded4_quaternary_unpacked");
    const auto& selected =
        find("bounded4_quaternary_packed4_rows18");
    const auto& packed6 =
        find("bounded4_quaternary_packed6_rows18");
    const auto& packed7 =
        find("bounded4_quaternary_packed7_rows18");
    const auto& wider_rejection =
        find("bounded8_quaternary_packed4_rows18");
    const auto& unsupported =
        find("bounded4_arity16_packed4_rows18");
    for (const auto& scenario : scenarios) {
        const auto hybrid = scenario.finite
            ? nr::AssessFriDualQ128HybridBound(
                  scenario.total_proof_sites,
                  nr::FriDualCommitmentTopology::SharedMaster)
            : nr::FriDualQ128HybridBoundAssessment{};
        BOOST_TEST_MESSAGE(
            scenario.name << ": total="
                          << scenario.total_proof_sites
                          << " cap=2^"
                          << scenario.union_bound_log2
                          << " finite=" << scenario.finite
                          << " supported="
                          << scenario.recursive_arity_supported
                          << " composed_shared_bits="
                          << hybrid.composed_union_bits);
    }
    BOOST_CHECK(binary.finite);
    BOOST_CHECK(selected.finite);
    BOOST_CHECK(selected.selected);
    BOOST_CHECK(selected.recursive_arity_supported);
    BOOST_CHECK_LT(
        selected.total_proof_sites, unpacked.total_proof_sites);
    BOOST_CHECK_LT(
        packed6.total_proof_sites, selected.total_proof_sites);
    BOOST_CHECK_LT(
        packed7.total_proof_sites, packed6.total_proof_sites);
    const auto packed4_hybrid =
        nr::AssessFriDualQ128HybridBound(
            selected.total_proof_sites,
            nr::FriDualCommitmentTopology::SharedMaster);
    const auto packed6_hybrid =
        nr::AssessFriDualQ128HybridBound(
            packed6.total_proof_sites,
            nr::FriDualCommitmentTopology::SharedMaster);
    const auto packed7_hybrid =
        nr::AssessFriDualQ128HybridBound(
            packed7.total_proof_sites,
            nr::FriDualCommitmentTopology::SharedMaster);
    BOOST_CHECK_CLOSE(
        packed4_hybrid.composed_union_bits,
        102.0196358875, 1e-7);
    BOOST_CHECK_CLOSE(
        packed6_hybrid.composed_union_bits,
        102.3199831560, 1e-7);
    BOOST_CHECK_CLOSE(
        packed7_hybrid.composed_union_bits,
        102.4215489353, 1e-7);
    BOOST_CHECK_LT(
        selected.total_proof_sites, binary.total_proof_sites);
    BOOST_CHECK_GT(
        wider_rejection.total_proof_sites,
        selected.total_proof_sites);
    BOOST_CHECK(unsupported.finite);
    BOOST_CHECK(
        !unsupported.recursive_arity_supported);
    BOOST_CHECK_LT(
        unsupported.total_proof_sites,
        selected.total_proof_sites);
}

BOOST_AUTO_TEST_CASE(
    single_q192_packed6_and_packed7_clear_only_global_collision_screen)
{
    const auto scenarios =
        ss::AssessSingleQ192PackingScenarios();
    BOOST_REQUIRE_EQUAL(scenarios.size(), 3U);
    const auto find = [&](uint8_t lanes)
        -> const ss::SingleQ192PackingAssessment& {
        const auto it = std::find_if(
            scenarios.begin(), scenarios.end(),
            [&](const auto& value) {
                return
                    value.hash_parallel_lanes ==
                    lanes;
            });
        BOOST_REQUIRE(it != scenarios.end());
        return *it;
    };
    const auto& packed4 = find(4);
    const auto& packed6 = find(6);
    const auto& packed7 = find(7);

    BOOST_CHECK_EQUAL(
        packed4.global_sites, 66'480'699ULL);
    BOOST_CHECK_EQUAL(
        packed6.global_sites, 57'648'003ULL);
    BOOST_CHECK_EQUAL(
        packed7.global_sites, 55'124'366ULL);
    BOOST_CHECK_CLOSE(
        packed4.fri_bits, 99.9470458309, 1e-7);
    BOOST_CHECK_CLOSE(
        packed6.fri_bits, 100.1527107501, 1e-7);
    BOOST_CHECK_CLOSE(
        packed7.fri_bits, 100.2172912241, 1e-7);
    BOOST_CHECK_CLOSE(
        packed6.per_site_composed_bits,
        99.8438439234, 1e-7);
    BOOST_CHECK_CLOSE(
        packed7.per_site_composed_bits,
        99.9084243974, 1e-7);
    BOOST_CHECK_CLOSE(
        packed6.global_first_collision_composed_bits,
        100.1527107442, 1e-7);
    BOOST_CHECK_CLOSE(
        packed7.global_first_collision_composed_bits,
        100.2172912179, 1e-7);

    BOOST_CHECK_EQUAL(packed6.trace_width, 912U);
    BOOST_CHECK_EQUAL(
        packed6.trace_width_headroom, 180U);
    BOOST_CHECK_EQUAL(packed7.trace_width, 1064U);
    BOOST_CHECK_EQUAL(
        packed7.trace_width_headroom, 28U);
    for (const auto& scenario : scenarios) {
        BOOST_CHECK(
            scenario.
                width_and_trace_schedule_executable);
        BOOST_CHECK(
            !scenario.
                global_first_collision_reduction_complete);
        BOOST_CHECK(!scenario.authority_eligible);
    }
    BOOST_CHECK(
        packed4.quotient_proof_wrapper_executable);
    BOOST_CHECK(
        !packed6.quotient_proof_wrapper_executable);
    BOOST_CHECK(
        !packed7.quotient_proof_wrapper_executable);
}

BOOST_AUTO_TEST_CASE(
    global_soundness_v1_is_additive_numeric_and_fail_closed)
{
    const auto assessment =
        ss::AssessGlobalSoundnessV1();
    BOOST_REQUIRE(assessment.parameters_valid);
    BOOST_CHECK_EQUAL(
        assessment.global_sites,
        37'488'397ULL);
    BOOST_CHECK_CLOSE(
        assessment.global_site_log2,
        25.1599408017, 1e-7);
    BOOST_CHECK_EQUAL(
        assessment.grinding_bits, 40U);
    BOOST_CHECK_EQUAL(
        assessment.trace_width_cap, 16'384U);
    BOOST_CHECK_EQUAL(
        assessment.constraint_count_cap,
        1U << 14);
    BOOST_CHECK_EQUAL(
        assessment.hash_collision_floor_bits,
        128U);
    BOOST_CHECK_EQUAL(
        assessment.hash_binding_events_per_site,
        1U);

    BOOST_CHECK_CLOSE(
        assessment.coarse_q192_fri_bits,
        100.7735372436, 1e-7);
    BOOST_CHECK_CLOSE(
        assessment.exact_q192_fri_bits,
        101.7735372173, 1e-7);
    BOOST_CHECK_CLOSE(
        assessment.dual_q136_fri_bits,
        111.5250799950, 1e-7);
    BOOST_CHECK_CLOSE(
        assessment.trace_batching_bits,
        109.8398830988, 1e-7);
    BOOST_CHECK_CLOSE(
        assessment.constraint_batching_bits,
        109.8400591983, 1e-7);
    BOOST_CHECK_CLOSE(
        assessment.hash_binding_bits,
        102.8400591983, 1e-7);
    BOOST_CHECK_CLOSE(
        assessment.coarse_q192_known_terms_bits,
        100.4603322660, 1e-7);
    BOOST_CHECK_CLOSE(
        assessment.exact_q192_known_terms_bits,
        101.2031426943, 1e-7);
    BOOST_CHECK_CLOSE(
        assessment.dual_q136_known_terms_bits,
        102.8142428026, 1e-7);

    BOOST_CHECK(
        assessment.canonical_site_manifest_derived);
    BOOST_CHECK(
        !assessment.
            canonical_site_manifest_backend_enforced);
    BOOST_CHECK(
        assessment.
            multirow_v2_post_claim_batching_executable);
    BOOST_CHECK(assessment.split_rap_air_executable);
    BOOST_CHECK(assessment.split_rap_uses_single_q192);
    BOOST_CHECK(
        assessment.dual_q136_backend_executable);
    BOOST_CHECK(
        !assessment.dual_q136_split_rap_integrated);
    BOOST_CHECK(
        assessment.coarse_q192_numeric_target_met);
    BOOST_CHECK(
        assessment.exact_q192_numeric_target_met);
    BOOST_CHECK(
        assessment.dual_q136_numeric_target_met);

    BOOST_CHECK(
        !assessment.semantic_closure_complete);
    BOOST_CHECK(
        !assessment.recursive_consumption_complete);
    BOOST_CHECK(
        !assessment.ali_degree_manifest_complete);
    BOOST_CHECK(
        !assessment.ctl_event_manifest_complete);
    BOOST_CHECK(
        !assessment.
            fiat_shamir_query_manifest_complete);
    BOOST_CHECK(!assessment.protocol_match_complete);
    BOOST_CHECK(
        !assessment.
            hash_binding_reduction_complete);
    BOOST_CHECK(
        !assessment.global_additive_union_complete);
    BOOST_CHECK(
        !assessment.
            deterministic_prerequisites_complete);
    BOOST_CHECK(!assessment.theorem_complete);
    BOOST_CHECK_EQUAL(assessment.certified_bits, 0U);
    BOOST_CHECK(!assessment.authority_eligible);
    BOOST_REQUIRE_EQUAL(assessment.terms.size(), 10U);
    for (const auto& term : assessment.terms) {
        BOOST_CHECK(!term.reduction_complete);
    }
}

BOOST_AUTO_TEST_CASE(
    global_soundness_v1_hash_and_pow_scenarios_are_explicit)
{
    const auto t12_three =
        ss::AssessGlobalSoundnessV1(
            1U << 14, 128, 3,
            ss::GlobalSoundnessV1PowHashAccountingMode::
                TotalAdversaryWorkIncluded);
    BOOST_REQUIRE(t12_three.parameters_valid);
    BOOST_CHECK_CLOSE(
        t12_three.hash_binding_bits,
        101.2550966976, 1e-7);
    BOOST_CHECK(
        t12_three.dual_q136_numeric_target_met);
    BOOST_CHECK_EQUAL(t12_three.certified_bits, 0U);

    const auto t12_six =
        ss::AssessGlobalSoundnessV1(
            1U << 14, 128, 6,
            ss::GlobalSoundnessV1PowHashAccountingMode::
                TotalAdversaryWorkIncluded);
    BOOST_REQUIRE(t12_six.parameters_valid);
    BOOST_CHECK_CLOSE(
        t12_six.hash_binding_bits,
        100.2550966976, 1e-7);
    BOOST_CHECK(
        t12_six.dual_q136_numeric_target_met);

    const auto per_attempt =
        ss::AssessGlobalSoundnessV1(
            1U << 14, 128, 1,
            ss::GlobalSoundnessV1PowHashAccountingMode::
                PerAttemptProbability);
    BOOST_REQUIRE(per_attempt.parameters_valid);
    BOOST_CHECK_CLOSE(
        per_attempt.hash_binding_bits,
        62.8400591983, 1e-7);
    BOOST_CHECK(
        !per_attempt.dual_q136_numeric_target_met);

    const auto t16 =
        ss::AssessGlobalSoundnessV1(
            1U << 14, 255, 6,
            ss::GlobalSoundnessV1PowHashAccountingMode::
                PerAttemptProbability);
    BOOST_REQUIRE(t16.parameters_valid);
    BOOST_CHECK_CLOSE(
        t16.hash_binding_bits,
        187.2550966976, 1e-7);
    BOOST_CHECK(t16.exact_q192_numeric_target_met);
    BOOST_CHECK(t16.dual_q136_numeric_target_met);
    BOOST_CHECK_EQUAL(t16.certified_bits, 0U);
    BOOST_CHECK(!t16.authority_eligible);

    const auto invalid =
        ss::AssessGlobalSoundnessV1(
            0, 128, 1,
            ss::GlobalSoundnessV1PowHashAccountingMode::
                TotalAdversaryWorkIncluded);
    BOOST_CHECK(!invalid.parameters_valid);
    BOOST_CHECK_EQUAL(invalid.certified_bits, 0U);
    BOOST_CHECK(!invalid.authority_eligible);
}

BOOST_AUTO_TEST_CASE(
    recursive_backend_tactics_are_topology_aware_and_fail_closed)
{
    const auto comparison =
        ss::AssessRecursiveBackendComparisonV1();
    BOOST_CHECK_EQUAL(
        comparison.current_global_sites,
        37'488'397ULL);
    BOOST_CHECK_EQUAL(
        comparison.relation_local_instances, 326U);
    BOOST_CHECK_EQUAL(
        comparison.product_topology_sites,
        12'221'217'422ULL);
    BOOST_CHECK_CLOSE(
        comparison.product_topology_log2,
        33.5086689559, 1e-7);
    BOOST_CHECK(
        !comparison
             .relation_local_nodes_in_current_manifest);
    BOOST_CHECK(
        !comparison
             .product_topology_is_production_theorem);
    BOOST_CHECK(
        comparison
            .canonical_heterogeneous_topology_manifest_derived);
    BOOST_CHECK(
        !comparison
             .width_planner_instances_are_site_multiplicity);
    BOOST_CHECK(comparison.product_topology_rejected);
    BOOST_CHECK(
        comparison
            .universal_program_selection_binding_defined);
    BOOST_CHECK(
        !comparison
             .universal_program_selection_consumed_in_recursive_air);
    BOOST_REQUIRE_EQUAL(
        comparison.scenarios.size(), 3U);

    const auto& q192 = comparison.scenarios[0];
    BOOST_CHECK(
        q192.tactic ==
        ss::RecursiveBackendTacticV1::
            ExecutableSingleFp3Q192);
    BOOST_CHECK(q192.proof_primitive_executable);
    BOOST_CHECK(q192.split_rap_integrated);
    BOOST_CHECK(
        q192.selected_executable_baseline);
    BOOST_CHECK_GT(q192.per_proof_fri_bits, 109.0);
    BOOST_CHECK(
        !q192.recursive_verifier_air_executable);
    BOOST_CHECK(!q192.formal_reduction_complete);

    const auto& dual = comparison.scenarios[1];
    BOOST_CHECK(
        dual.tactic ==
        ss::RecursiveBackendTacticV1::
            DuplicatedDomainSeparatedFp3Q136);
    BOOST_CHECK(dual.proof_primitive_executable);
    BOOST_CHECK(
        dual.fully_duplicated_lane_commitments);
    BOOST_CHECK(!dual.split_rap_integrated);
    BOOST_CHECK(
        !dual.full_oracle_domain_separation_proven);
    BOOST_CHECK_GT(
        dual.product_topology_fri_bits, 100.0);

    const auto& fp4 = comparison.scenarios[2];
    BOOST_CHECK(
        fp4.tactic ==
        ss::RecursiveBackendTacticV1::
            HypotheticalFp4Q192);
    BOOST_CHECK(!fp4.proof_primitive_executable);
    BOOST_CHECK_GT(
        fp4.product_topology_fri_bits,
        q192.product_topology_fri_bits);

    BOOST_CHECK(
        comparison
            .at_least_one_proof_primitive_executable);
    BOOST_CHECK(
        comparison
            .at_least_one_split_rap_path_executable);
    BOOST_CHECK(
        !comparison
             .any_109_bit_formal_recursive_backend);
    BOOST_CHECK_EQUAL(comparison.certified_bits, 0U);
    BOOST_CHECK(!comparison.authority_eligible);
}

// ============================================================================
// PR-89: corrected honest dual-lane floor (Pi_JQ joint query squeeze +
// enforced per-squeeze grinding tax). Replaces the fictional flat-(-40) /
// per-lane Log2BcsError^lanes multiplication for the reported floor.
// ============================================================================
BOOST_AUTO_TEST_CASE(pr89_honest_dual_floor_replaces_fiction)
{
    // Direct helper: min(hash birthday 128, dual query PAIR) at g=40.
    BOOST_CHECK_CLOSE(ss::Fri3AlgHonestDualFloorBits(64, 40), 128.0, 1e-9);
    BOOST_CHECK_CLOSE(ss::Fri3AlgHonestDualFloorBits(80, 40), 96.0, 1e-9);
    BOOST_CHECK_CLOSE(ss::Fri3AlgHonestDualFloorBits(100, 40), 56.0, 1e-9);

    // Hash-birthday floor caps the reported number: even a tiny q cannot exceed
    // the SHA256d 128-bit collision floor.
    BOOST_CHECK_CLOSE(ss::Fri3AlgHonestDualFloorBits(8, 40), 128.0, 1e-9);

    // The ledger scenario reports the same honest floor, and it is NOT the
    // fictional single-screen number (~101.x) or the untaxed all-query value.
    struct {
        uint32_t q;
        double floor;
    } cases[] = {{64, 128.0}, {80, 96.0}, {100, 56.0}};
    for (const auto& c : cases) {
        const ss::FriScenario s = ss::AssessFriScenario(
            "pr89_jointq", 2, c.q, 3, 24,
            ss::BatchChallengeShape::IndependentCoefficients, 1ULL << 28,
            1U << 14, 256, 40, /*joint_query_squeeze=*/true,
            /*per_squeeze_grind_g=*/40);
        BOOST_REQUIRE(s.parameters_valid);
        BOOST_CHECK(s.joint_query_squeeze);
        BOOST_CHECK_EQUAL(s.per_squeeze_grind_g, 40U);
        BOOST_CHECK_CLOSE(s.hash_birthday_bits, 128.0, 1e-9);
        BOOST_CHECK_CLOSE(s.honest_floor_bits, c.floor, 1e-9);
        // Corrected floor differs from the fictional lanes-multiplication value.
        BOOST_CHECK(std::abs(s.honest_floor_bits - 101.20) > 1.0);
    }

    // q -> q-g at the taxed round: raising g lifts the dual query PAIR term
    // one-for-one (net of the joint-squeeze pairing loss), and g=0 (no enforced
    // tax) reports a strictly lower floor than g=40.
    const ss::FriScenario taxed = ss::AssessFriScenario(
        "pr89_q80_g40", 2, 80, 3, 24,
        ss::BatchChallengeShape::IndependentCoefficients, 1ULL << 28, 1U << 14,
        256, 40, true, 40);
    const ss::FriScenario untaxed = ss::AssessFriScenario(
        "pr89_q80_g0", 2, 80, 3, 24,
        ss::BatchChallengeShape::IndependentCoefficients, 1ULL << 28, 1U << 14,
        256, 40, true, 0);
    BOOST_CHECK_GT(taxed.honest_floor_bits, untaxed.honest_floor_bits);
    // At q=80, dual_query_pair grows by exactly (g2-g1) between two taxed g's.
    const ss::FriScenario taxed20 = ss::AssessFriScenario(
        "pr89_q80_g20", 2, 80, 3, 24,
        ss::BatchChallengeShape::IndependentCoefficients, 1ULL << 28, 1U << 14,
        256, 40, true, 20);
    BOOST_CHECK_CLOSE(taxed.dual_query_pair_bits - taxed20.dual_query_pair_bits,
                      20.0, 1e-9);

    // Neither the corrected screen nor any authority flag is promoted.
    BOOST_CHECK(!ss::kSoundnessScenarioCertified);
    BOOST_CHECK(!ss::kSoundnessScenarioAuthorityReady);
}

BOOST_AUTO_TEST_CASE(
    composed_threat_model_floor_binds_on_shared_collision_at_qstar)
{
    // q* = 76 over the canonical 37,488,397-site ledger count.
    const auto f = ss::AssessComposedThreatModelFloorV1(
        ss::kThreatModelDefensibleMinQStar, 37'488'397ULL);
    BOOST_CHECK_EQUAL(f.qstar, 76U);
    BOOST_CHECK_CLOSE(f.field_pair_bits, 156.0, 1e-9);
    BOOST_CHECK_CLOSE(f.taxed_query_pair_bits, 212.0, 1e-9);
    BOOST_CHECK_CLOSE(f.shared_collision_bits, 104.0, 1e-9);
    BOOST_CHECK(
        f.binding_term ==
        ss::ComposedFloorBindingTerm::SharedCollision);
    BOOST_CHECK_CLOSE(f.per_site_composed_floor_bits, 104.0, 1e-9);
    BOOST_CHECK_CLOSE(f.global_composed_floor_bits, 79.0, 1e-9);
    BOOST_CHECK(f.per_site_meets_100);
    BOOST_CHECK(!f.global_meets_100);
    BOOST_CHECK(f.global_meets_64);
    BOOST_REQUIRE_EQUAL(f.assumptions.size(), 4U);

    // Doc table row q = 78 (stress ceiling): F = min(152, 210, 100) = 100.
    const auto s = ss::AssessComposedThreatModelFloorV1(
        ss::kThreatModelStressCeilingQ, 0);
    BOOST_CHECK_CLOSE(s.shared_collision_bits, 100.0, 1e-9);
    BOOST_CHECK_CLOSE(s.per_site_composed_floor_bits, 100.0, 1e-9);
    BOOST_CHECK(s.per_site_meets_100);

    // Doc table row q = 64: shared-collision term 128 binds.
    const auto q64 = ss::AssessComposedThreatModelFloorV1(64, 0);
    BOOST_CHECK_CLOSE(q64.per_site_composed_floor_bits, 128.0, 1e-9);

    // No screen promotes any authority flag.
    BOOST_CHECK(!ss::kSoundnessScenarioCertified);
    BOOST_CHECK(!ss::kSoundnessScenarioAuthorityReady);
}

// PR-89 gate 3: the executable single-lane rbr/BCS ledger reads the actual
// construction constants and reproduces each per-round bound.
BOOST_AUTO_TEST_CASE(fra3_bcs_rbr_ledger_per_round_bounds)
{
    const auto ledger = ss::AssessFri3AlgBcsRbrLedgerV1();

    // Parameters are read straight from the compiled FRI construction.
    BOOST_CHECK_EQUAL(ledger.queries, rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(ledger.queries, 192U);
    BOOST_CHECK_EQUAL(ledger.extension_degree, 3U);
    BOOST_CHECK_EQUAL(ledger.blowup, rc::kRCFriBlowup);
    BOOST_CHECK_EQUAL(ledger.blowup, 16U);
    BOOST_CHECK_EQUAL(ledger.grinding_bits, rc::kRCFriGrindingBits);
    BOOST_CHECK_EQUAL(ledger.lde_log2, 24U);
    BOOST_CHECK(ledger.parameters_match_construction);

    // |Fp3| ~ 2^192, rho = 1/16 (rho^-1 = 2^4), alpha = 17/32.
    BOOST_CHECK_CLOSE(ledger.field_cardinality_bits, 192.0, 1e-6);
    BOOST_CHECK_CLOSE(ledger.rho_inverse_log2, 4.0, 1e-9);
    BOOST_CHECK_CLOSE(ledger.alpha_log2_ratio, std::log2(32.0 / 17.0), 1e-9);

    // Five round kinds: 4 field rounds + 1 query phase.
    BOOST_REQUIRE_EQUAL(ledger.rounds.size(), 5U);

    auto find = [&](ss::Fri3AlgRbrRoundKind k)
        -> const ss::Fri3AlgRbrRoundBoundV1* {
        for (const auto& r : ledger.rounds)
            if (r.kind == k) return &r;
        return nullptr;
    };

    // Batching correlated agreement: the BINDING field round ~151 (charges the
    // published proximity-gap theorem constant).
    const auto* batch =
        find(ss::Fri3AlgRbrRoundKind::BatchingCorrelatedAgreement);
    BOOST_REQUIRE(batch != nullptr);
    BOOST_CHECK(batch->field_round);
    BOOST_CHECK_CLOSE(batch->per_round_bits, 150.9335, 0.01);
    BOOST_CHECK(batch->in_proven_field_window);

    // Dual-OOD DEEP and DEEP-weight line-CA: ~167.
    const auto* ood = find(ss::Fri3AlgRbrRoundKind::DualOodDeep);
    const auto* deepw = find(ss::Fri3AlgRbrRoundKind::DeepWeightLineCA);
    BOOST_REQUIRE(ood != nullptr);
    BOOST_REQUIRE(deepw != nullptr);
    BOOST_CHECK_CLOSE(ood->per_round_bits, 167.0, 0.01);
    BOOST_CHECK_CLOSE(deepw->per_round_bits, 167.0, 0.01);
    BOOST_CHECK(ood->in_proven_field_window);
    BOOST_CHECK(deepw->in_proven_field_window);

    // Fold-round line-CA: the lightest field round ~168, multiplicity = folds.
    const auto* fold = find(ss::Fri3AlgRbrRoundKind::FoldRoundLineCA);
    BOOST_REQUIRE(fold != nullptr);
    BOOST_CHECK_CLOSE(fold->per_round_bits, 168.0, 0.01);
    BOOST_CHECK_EQUAL(fold->multiplicity, 20U); // lde_log2 - rho^-1_log2
    BOOST_CHECK(fold->in_proven_field_window);

    // Every field round lands in the proven [151,168] window (m_f ~ 154).
    BOOST_CHECK(ledger.every_field_round_in_proven_window);
    BOOST_CHECK_GE(ledger.min_field_round_bits, 150.5);
    BOOST_CHECK_LE(ledger.max_field_round_bits, 168.5);
    BOOST_CHECK_CLOSE(ledger.field_round_mf_bits, 154.0, 1e-9);

    // Query proximity phase == Fri3AlgSoundnessBoundBits() == 135.
    const auto* query = find(ss::Fri3AlgRbrRoundKind::QueryProximity);
    BOOST_REQUIRE(query != nullptr);
    BOOST_CHECK(!query->field_round);
    BOOST_CHECK_CLOSE(query->per_round_bits,
                      static_cast<double>(rc::Fri3AlgSoundnessBoundBits()),
                      1e-9);
    BOOST_CHECK_CLOSE(query->per_round_bits, 135.0, 1e-9);
}

BOOST_AUTO_TEST_CASE(fra3_bcs_rbr_ledger_composition_135_over_128)
{
    const auto ledger = ss::AssessFri3AlgBcsRbrLedgerV1();

    // BCS state restoration: t interactive rounds (24 = 3 field + 20 folds +
    // 1 query round), log2(t) ~ 4.585 bits, random-oracle term 3(Q^2+1)/2^256
    // negligible (>200 bits of margin).
    BOOST_CHECK_EQUAL(ledger.fri_rbr_round_count, 24U);
    BOOST_CHECK_CLOSE(ledger.bcs_state_restoration_charge_bits,
                      std::log2(24.0), 1e-6);
    BOOST_CHECK_GT(ledger.bcs_random_oracle_term_bits, 200.0);
    BOOST_CHECK(ledger.bcs_reduction_numerically_instantiated);

    // Even the worst field round after the BCS charge stays above 135, so the
    // field side is NON-BINDING.
    BOOST_CHECK(ledger.field_rounds_non_binding);
    BOOST_CHECK_GE(ledger.min_field_round_after_bcs_bits, 135.0);

    // Headline 135/128: query proximity 135, shared Poseidon2 collision 128,
    // composed single-lane floor = min = 128.
    BOOST_CHECK_CLOSE(ledger.query_proximity_floor_bits, 135.0, 1e-9);
    BOOST_CHECK_CLOSE(ledger.hash_collision_floor_bits, 128.0, 1e-9);
    BOOST_CHECK_CLOSE(ledger.composed_single_lane_floor_bits, 128.0, 1e-9);
    BOOST_CHECK(ledger.query_proximity_matches_construction);
    BOOST_CHECK(ledger.hash_collision_floor_matches_construction);
    BOOST_CHECK(ledger.composition_reproduces_135_128);

    // The full machine-check verdict that gate 3 asserts.
    BOOST_CHECK(ledger.rbr_reduction_machine_checked);
    BOOST_CHECK_EQUAL(ledger.rbr_reduction_machine_checked,
                      rc::kRCFri3AlgFormalSoundnessReady);

    // Disclosed published-theorem assumptions (audit-input), NOT gaps.
    BOOST_REQUIRE_EQUAL(ledger.assumptions.size(), 3U);
    BOOST_CHECK_EQUAL(ledger.assumptions[0].tag,
                      "proximity_gap:BKS2018_BCIKS2020_Haboeck2022");
    BOOST_CHECK(ledger.assumptions[0].status ==
                ss::ComposedFloorAssumptionStatus::ProvenAuditInput);
    BOOST_CHECK_EQUAL(ledger.assumptions[1].tag,
                      "bcs_transform:BCS2016_Block2023");
    BOOST_CHECK(ledger.assumptions[1].status ==
                ss::ComposedFloorAssumptionStatus::ProvenAuditInput);
    BOOST_CHECK_EQUAL(ledger.assumptions[2].tag,
                      "hash_model:poseidon2_capacity_128");
    BOOST_CHECK(ledger.assumptions[2].audit_input);
    for (const auto& a : ledger.assumptions) BOOST_CHECK(a.audit_input);
}

BOOST_AUTO_TEST_SUITE_END()
