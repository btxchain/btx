// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_stage3_episode_header_target.h>
#include <matmul/matmul_v4_rc_stage3_narrow_recurse.h>
#include <matmul/matmul_v4_rc_stage3_aggregation_schedule.h>
#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <arith_uint256.h>
#include <consensus/params.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_stage3.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_role_sections.h>
#include <pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <string>
#include <vector>

namespace aq = matmul::v4::rc::air_quotient;
namespace ar = matmul::v4::rc::air_recurse;
namespace fpx = matmul::v4::rc::recursive_fixedpoint;
namespace gfx = matmul::v4::rc::gkr_field;
namespace nr = matmul::v4::rc::narrow_recurse;
namespace rcx = matmul::v4::rc;
namespace ss = matmul::v4::rc::soundness_scenarios;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_narrow_recurse_tests)

BOOST_AUTO_TEST_CASE(canonical_lane_is_contiguous_and_192_columns)
{
    const nr::NarrowLaneLayout lane = nr::CanonicalNarrowLaneLayout();
    std::string why;
    BOOST_CHECK_MESSAGE(lane.IsCanonical(&why), why);
    BOOST_CHECK_EQUAL(lane.width, 192U);
    BOOST_CHECK_EQUAL(lane.permutation.count, 130U);
    BOOST_CHECK_EQUAL(lane.reserved.End(), lane.width);
}

// ---------------------------------------------------------------------------
// Hierarchical narrow aggregation under row/LDE budgets (recommendation #3).
// Cheap COMPUTED shape arithmetic — no prove, no BTX_RUN_BLK_NARROW.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(narrow_node_fri_shape_pins_lde_budget_at_degree_three)
{
    // At degree 3, trace 2^19 -> quotient ~2^20, n_lde 2^24: FITS exactly.
    const nr::NarrowNodeFriShape fits = nr::AssessNarrowNodeFriShape(473664);
    BOOST_CHECK_EQUAL(fits.trace_rows, 1U << 19);
    BOOST_CHECK_EQUAL(fits.n_lde, 1U << 24);
    BOOST_CHECK(fits.representable);
    BOOST_CHECK(fits.fits_column_cap);
    BOOST_CHECK_EQUAL(fits.vcs_columns, nr::kMeasuredNarrowComposedColumns);

    // One more doubling of the trace blows the LDE cap.
    const nr::NarrowNodeFriShape over =
        nr::AssessNarrowNodeFriShape(uint64_t{1} << 19);
    // active == 2^19 pads to 2^19 and still fits; active just over needs 2^20.
    const nr::NarrowNodeFriShape over2 =
        nr::AssessNarrowNodeFriShape((uint64_t{1} << 19) + 1);
    BOOST_CHECK(over.representable);
    BOOST_CHECK(!over2.representable);
    BOOST_CHECK_EQUAL(over2.trace_rows, 1U << 20);
    BOOST_CHECK_EQUAL(over2.n_lde, 1U << 25);
}

BOOST_AUTO_TEST_CASE(canonical_six_episode_narrow_hierarchy_fits_under_budgets)
{
    const nr::NarrowHierarchicalAggregationPlan plan =
        nr::PlanCanonicalSixEpisodeNarrowHierarchy();
    BOOST_REQUIRE_MESSAGE(plan.valid, plan.note);
    BOOST_CHECK(!plan.single_level_fits);
    BOOST_CHECK(plan.hierarchical_fits);
    BOOST_CHECK(plan.all_leaves_covered);
    BOOST_CHECK(!plan.complete_verifier_mirror);
    BOOST_CHECK_EQUAL(plan.leaf_count, 6U);
    BOOST_CHECK_EQUAL(plan.node_count, 3U);
    BOOST_CHECK_EQUAL(plan.depth, 2U);
    BOOST_CHECK_EQUAL(plan.vcs_columns, 575U);

    // Single-level over all six is the known 854,400-row wall.
    BOOST_CHECK_EQUAL(plan.single_level_shape.active_rows, 854400U);
    BOOST_CHECK(!plan.single_level_shape.representable);
    BOOST_CHECK_EQUAL(plan.single_level_shape.n_lde, 1U << 25);

    BOOST_REQUIRE_EQUAL(plan.nodes.size(), 3U);
    // L1-A gemm+wiring+tiletree+digest
    BOOST_CHECK_EQUAL(plan.nodes[0].level, 1U);
    BOOST_CHECK_EQUAL(plan.nodes[0].active_rows, 473664U);
    BOOST_CHECK(plan.nodes[0].shape.representable);
    BOOST_CHECK_EQUAL(plan.nodes[0].child_leaf_indices.size(), 4U);
    BOOST_CHECK_EQUAL(plan.nodes[0].child_leaf_indices[0], 1U);
    BOOST_CHECK_EQUAL(plan.nodes[0].child_leaf_indices[1], 3U);
    BOOST_CHECK_EQUAL(plan.nodes[0].child_leaf_indices[2], 4U);
    BOOST_CHECK_EQUAL(plan.nodes[0].child_leaf_indices[3], 5U);
    // L1-B builder+extract
    BOOST_CHECK_EQUAL(plan.nodes[1].level, 1U);
    BOOST_CHECK_EQUAL(plan.nodes[1].active_rows, 380736U);
    BOOST_CHECK(plan.nodes[1].shape.representable);
    BOOST_CHECK_EQUAL(plan.nodes[1].child_leaf_indices.size(), 2U);
    BOOST_CHECK_EQUAL(plan.nodes[1].child_leaf_indices[0], 0U);
    BOOST_CHECK_EQUAL(plan.nodes[1].child_leaf_indices[1], 2U);
    // L2 over both L1 proofs
    BOOST_CHECK_EQUAL(plan.nodes[2].level, 2U);
    BOOST_CHECK_EQUAL(plan.nodes[2].active_rows, 515328U);
    BOOST_CHECK(plan.nodes[2].shape.representable);
    BOOST_CHECK_EQUAL(plan.nodes[2].child_node_indices.size(), 2U);
    BOOST_CHECK_EQUAL(plan.nodes[2].shape.n_lde, 1U << 24);
    BOOST_CHECK_LE(plan.nodes[2].shape.vcs_columns,
                   matmul::v4::rc::kRCFri3AlgBatchMaxColumns);

    // Headroom at L2: 515328 / 524288 ≈ 1.7% spare before the next doubling.
    BOOST_CHECK_LT(plan.nodes[2].active_rows, plan.nodes[2].shape.trace_rows);
    BOOST_CHECK_EQUAL(plan.nodes[2].shape.trace_rows, 1U << 19);

    BOOST_CHECK(nr::kNarrowHierarchicalAggregationPlannerExecutable);
    BOOST_CHECK(!nr::kNarrowHierarchicalAggregationReady);
}

BOOST_AUTO_TEST_CASE(hierarchical_packer_closes_six_roles_when_single_level_cannot)
{
    std::vector<nr::NarrowHierarchyLeaf> leaves;
    static constexpr std::array<const char*, 6> kNames = {
        "episode:builder", "episode:gemm", "episode:extract",
        "episode:wiring", "episode:tiletree", "episode:digest",
    };
    for (uint32_t i = 0; i < 6; ++i) {
        nr::NarrowHierarchyLeaf leaf;
        leaf.role_index = i;
        leaf.name = kNames[i];
        leaf.active_rows = nr::kMeasuredSixEpisodeNarrowActiveRows[i];
        leaves.push_back(std::move(leaf));
    }
    const nr::NarrowHierarchicalAggregationPlan plan =
        nr::PlanHierarchicalNarrowAggregation(leaves);
    BOOST_REQUIRE_MESSAGE(plan.valid, plan.note);
    BOOST_CHECK(!plan.single_level_fits);
    BOOST_CHECK(plan.hierarchical_fits);
    BOOST_CHECK(plan.all_leaves_covered);
    BOOST_CHECK_GE(plan.depth, 2U);
    BOOST_CHECK_GE(plan.node_count, 3U);
    for (const nr::NarrowHierarchyNode& node : plan.nodes) {
        BOOST_CHECK_MESSAGE(node.shape.representable, node.label);
        BOOST_CHECK_LE(node.shape.vcs_columns,
                       matmul::v4::rc::kRCFri3AlgBatchMaxColumns);
        BOOST_CHECK_LE(uint64_t{node.shape.n_lde},
                       uint64_t{1} << matmul::v4::rc::kRCFriMaxLdeLog2);
    }
}

BOOST_AUTO_TEST_CASE(aggregation_schedule_reexports_narrow_hierarchy_plan)
{
    namespace sched = matmul::v4::rc::aggregation_scheduler;
    BOOST_CHECK(sched::kNarrowHierarchicalAggregationPlannerExecutable);
    BOOST_CHECK(!sched::kNarrowHierarchicalAggregationReady);
    const auto plan = sched::BuildNarrowHierarchicalSixEpisodePlan();
    BOOST_REQUIRE_MESSAGE(plan.valid, plan.note);
    BOOST_CHECK_EQUAL(plan.node_count, 3U);
    BOOST_CHECK_EQUAL(plan.nodes[0].active_rows, 473664U);
    BOOST_CHECK_EQUAL(plan.nodes[1].active_rows, 380736U);
    BOOST_CHECK_EQUAL(plan.nodes[2].active_rows, 515328U);
}

BOOST_AUTO_TEST_CASE(decomposed_x7_profile_has_explicit_x2_x4_and_degree_four)
{
    const nr::NarrowLaneLayout lane = nr::CanonicalNarrowLaneLayout(
        nr::PoseidonLaneStrategy::DecomposedX2X4);
    std::string why;
    BOOST_CHECK_MESSAGE(lane.IsCanonical(&why), why);
    BOOST_CHECK_EQUAL(lane.width, 428U);
    BOOST_CHECK_EQUAL(lane.sbox_x2.count, 118U);
    BOOST_CHECK_EQUAL(lane.sbox_x4.count, 118U);
    const nr::PoseidonConstraintProfile profile =
        nr::CanonicalPoseidonConstraintProfile(
            nr::PoseidonLaneStrategy::DecomposedX2X4);
    BOOST_CHECK_EQUAL(profile.auxiliary_columns, 236U);
    BOOST_CHECK_EQUAL(profile.constraints, 354U);
    BOOST_CHECK_EQUAL(profile.ungated_max_degree, 3U);
    BOOST_CHECK_EQUAL(profile.selector_degree, 1U);
    BOOST_CHECK_EQUAL(profile.gated_max_degree, 4U);
}

BOOST_AUTO_TEST_CASE(fully_quadratic_x7_profile_adds_x6_and_gates_to_degree_three)
{
    const nr::NarrowLaneLayout lane = nr::CanonicalNarrowLaneLayout(
        nr::PoseidonLaneStrategy::DecomposedX2X4X6);
    std::string why;
    BOOST_CHECK_MESSAGE(lane.IsCanonical(&why), why);
    BOOST_CHECK_EQUAL(lane.width, 546U);
    BOOST_CHECK_EQUAL(lane.sbox_x2.count, 118U);
    BOOST_CHECK_EQUAL(lane.sbox_x4.count, 118U);
    BOOST_CHECK_EQUAL(lane.sbox_x6.count, 118U);
    const nr::PoseidonConstraintProfile profile =
        nr::CanonicalPoseidonConstraintProfile(
            nr::PoseidonLaneStrategy::DecomposedX2X4X6);
    BOOST_CHECK_EQUAL(profile.auxiliary_columns, 354U);
    BOOST_CHECK_EQUAL(profile.constraints, 472U);
    BOOST_CHECK_EQUAL(profile.ungated_max_degree, 2U);
    BOOST_CHECK_EQUAL(profile.gated_max_degree, 3U);
}

BOOST_AUTO_TEST_CASE(production_schedule_closes_explicit_width_inequality)
{
    const nr::NarrowVcsPlan p =
        nr::BuildNarrowVcsPlan(nr::ProductionEpisodeChildShape());
    BOOST_REQUIRE_MESSAGE(p.valid, p.note);
    BOOST_CHECK(p.all_mandatory_families);
    BOOST_CHECK_EQUAL(p.parent_width, 192U);
    BOOST_CHECK_EQUAL(p.recursively_planned_width, 192U);
    BOOST_CHECK_LE(p.recursively_planned_width, p.parent_width);
    BOOST_CHECK(p.width_fixed_point);
    BOOST_CHECK_LE(p.parent_width,
                   matmul::v4::rc::kRCFri3AlgBatchMaxColumns);

    // Exact frozen production schedule:
    // row Merkle 11+20, folds 448, DEEP ceil(27/8), point ceil(13/8)+1,
    // two boundary rows, all at Q=128, plus 42 FS replay rows.
    BOOST_CHECK_EQUAL(
        p.families[static_cast<uint32_t>(nr::VerifierFamily::RowMerkle)]
            .rows_per_query,
        31U);
    BOOST_CHECK_EQUAL(
        p.families[static_cast<uint32_t>(nr::VerifierFamily::Fold)]
            .rows_per_query,
        448U);
    BOOST_CHECK_EQUAL(
        p.families[static_cast<uint32_t>(nr::VerifierFamily::Deep)]
            .rows_per_query,
        4U);
    BOOST_CHECK_EQUAL(
        p.families[static_cast<uint32_t>(nr::VerifierFamily::PerPoint)]
            .rows_per_query,
        3U);
    BOOST_CHECK_EQUAL(
        p.families[static_cast<uint32_t>(
                       nr::VerifierFamily::FiatShamirReplay)]
            .rows_per_child,
        42U);
    BOOST_CHECK_EQUAL(p.active_rows, 125012U);
    BOOST_CHECK_EQUAL(p.trace_rows, 1U << 17);
    BOOST_CHECK(p.backend_columns_supported);
    BOOST_CHECK(p.backend_lde_supported);
}

BOOST_AUTO_TEST_CASE(production_trace_shape_stabilizes_after_one_recursive_growth)
{
    const nr::NarrowVcsPlan leaf =
        nr::BuildNarrowVcsPlan(nr::ProductionEpisodeChildShape());
    BOOST_REQUIRE(leaf.valid);
    const nr::NarrowVcsPlan level1 =
        nr::BuildNarrowVcsPlan(nr::NextRecursiveChildShape(leaf));
    BOOST_REQUIRE_MESSAGE(level1.valid, level1.note);
    const nr::NarrowVcsPlan level2 =
        nr::BuildNarrowVcsPlan(nr::NextRecursiveChildShape(level1));
    BOOST_REQUIRE_MESSAGE(level2.valid, level2.note);

    BOOST_CHECK_EQUAL(leaf.parent_width, 192U);
    BOOST_CHECK_EQUAL(level1.parent_width, 192U);
    BOOST_CHECK_EQUAL(level2.parent_width, 192U);
    BOOST_CHECK_EQUAL(leaf.trace_rows, 1U << 17);
    BOOST_CHECK_EQUAL(level1.trace_rows, 1U << 18);
    BOOST_CHECK_EQUAL(level2.trace_rows, 1U << 18);
    BOOST_CHECK_EQUAL(level1.n_lde, 1U << 25);
    BOOST_CHECK_EQUAL(level2.n_lde, 1U << 25);
    BOOST_CHECK(!level1.backend_lde_supported);
    BOOST_CHECK(!level2.backend_lde_supported);
}

BOOST_AUTO_TEST_CASE(readiness_fails_if_one_verifier_family_is_missing)
{
    const uint32_t without_deep =
        nr::kNarrowMandatoryFamilyMask &
        ~nr::FamilyBit(nr::VerifierFamily::Deep);
    const nr::NarrowVcsPlan p = nr::BuildNarrowVcsPlan(
        nr::ProductionEpisodeChildShape(), without_deep);
    BOOST_REQUIRE(p.valid);
    BOOST_CHECK(!p.all_mandatory_families);
    const nr::NarrowVcsReadiness r = nr::AssessNarrowVcsReadiness(p);
    BOOST_CHECK(!r.all_mandatory_families);
    BOOST_CHECK(!r.production_ready);
}

BOOST_AUTO_TEST_CASE(readiness_reports_closed_shape_but_no_fake_proof)
{
    const nr::NarrowVcsPlan p =
        nr::BuildNarrowVcsPlan(nr::ProductionEpisodeChildShape());
    BOOST_REQUIRE(p.valid);
    const nr::NarrowVcsReadiness r = nr::AssessNarrowVcsReadiness(p);
    BOOST_CHECK(r.layout_valid);
    BOOST_CHECK(r.all_mandatory_families);
    BOOST_CHECK(r.width_fixed_point);
    BOOST_CHECK(r.trace_shape_fixed_point);
    BOOST_CHECK(!r.backend_shape_supported);
    BOOST_CHECK(!r.implementation_complete);
    BOOST_CHECK(!r.soundness_target_met);
    BOOST_CHECK(!r.performance_target_met);
    BOOST_CHECK(!r.production_ready);
    BOOST_CHECK_GE(r.gaps.size(), 4U);
    static_assert(!nr::kNarrowVcsExecutable);
    static_assert(!nr::kNarrowVcsProductionReady);
}

BOOST_AUTO_TEST_CASE(soundness_topologies_account_for_union_loss)
{
    const nr::NarrowSoundnessPlan q148 =
        nr::AssessNarrowSoundness(
            nr::SoundnessTopology::UnifiedMultiRoleRoot, 148, 14, 0, 0, true);
    BOOST_CHECK_GT(q148.raw_bits, 95.0);
    BOOST_CHECK_LT(q148.raw_bits, 96.0);
    BOOST_CHECK(!q148.target_met);

    const nr::NarrowSoundnessPlan independent =
        nr::AssessNarrowSoundness(
            nr::SoundnessTopology::IndependentRoleRoots, 159);
    BOOST_CHECK(independent.topology_complete);
    BOOST_CHECK_EQUAL(independent.union_sites, 14U);
    BOOST_CHECK_CLOSE(independent.union_loss_bits, std::log2(14.0), 0.001);
    BOOST_CHECK_GT(independent.raw_bits, 105.0);
    BOOST_CHECK_GT(independent.composed_bits, 101.0);
    BOOST_CHECK(independent.target_met);

    const nr::NarrowSoundnessPlan unified_missing_schema =
        nr::AssessNarrowSoundness(
            nr::SoundnessTopology::UnifiedMultiRoleRoot, 154);
    BOOST_CHECK_GE(unified_missing_schema.raw_bits, 100.0);
    BOOST_CHECK(!unified_missing_schema.topology_complete);
    BOOST_CHECK(!unified_missing_schema.target_met);

    const nr::NarrowSoundnessPlan unified =
        nr::AssessNarrowSoundness(
            nr::SoundnessTopology::UnifiedMultiRoleRoot, 154, 14, 0, 0, true);
    BOOST_CHECK(unified.topology_complete);
    BOOST_CHECK_EQUAL(unified.union_sites, 1U);
    BOOST_CHECK_GE(unified.composed_bits, 100.0);
    BOOST_CHECK(unified.target_met);

    // A large aggregation tree consumes margin. Per-proof "100 bits" is not
    // automatically a 100-bit global system.
    const nr::NarrowSoundnessPlan large_tree =
        nr::AssessNarrowSoundness(
            nr::SoundnessTopology::UnifiedMultiRoleRoot, 154, 14, 127, 0, true);
    BOOST_CHECK_EQUAL(large_tree.union_sites, 128U);
    BOOST_CHECK_CLOSE(large_tree.union_loss_bits, 7.0, 0.001);
    BOOST_CHECK(!large_tree.target_met);

    // Canonical Stage-3 topology: 14 relation leaves plus all 15 nodes in
    // the normalized 16-leaf binary aggregation tree. The unified-root API
    // accounts for one exposed root, so the other 28 fallible proof sites are
    // charged explicitly here.
    const nr::NarrowSoundnessPlan canonical_stage3 =
        nr::AssessNarrowSoundness(
            nr::SoundnessTopology::UnifiedMultiRoleRoot, 160, 14, 28, 0, true);
    BOOST_CHECK_EQUAL(canonical_stage3.union_sites, 29U);
    BOOST_CHECK_GT(canonical_stage3.composed_bits, 101.0);
    BOOST_CHECK(canonical_stage3.target_met);

    const nr::NarrowSoundnessPlan production_union =
        nr::AssessNarrowSoundness(
            nr::SoundnessTopology::UnifiedMultiRoleRoot,
            192, 14, (uint32_t{1} << 28) - 1, 0, true);
    BOOST_CHECK_EQUAL(
        production_union.union_sites, uint64_t{1} << 28);
    BOOST_CHECK_GT(production_union.composed_bits, 107.0);
    BOOST_CHECK(production_union.target_met);
}

BOOST_AUTO_TEST_CASE(formal_fri_field_term_favors_two_independent_q96_lanes)
{
    // A single Q=192 Fp3 lane passes the proximity-only diagnostic, but the
    // |L|^2/|F| term at a 2^24 LDE does not survive a 2^28 site budget and
    // 40-bit grinding at the 100-bit target.
    const nr::FriFormalMarginExperiment single =
        nr::AssessFriFormalMarginExperiment(1, 192);
    BOOST_CHECK_GT(single.proximity_bits_after_losses, 107.0);
    BOOST_CHECK_CLOSE(single.field_domain_bits_after_losses, 76.0, 0.001);
    BOOST_CHECK_CLOSE(single.bottleneck_bits, 76.0, 0.001);
    BOOST_CHECK(!single.parameter_target_met);
    BOOST_CHECK(!single.formal_reduction_complete);
    BOOST_CHECK(!single.authority_eligible);

    // Two domain-separated Q=96 lanes keep the same total query count. If a
    // future composition proof establishes conditional independence, both
    // modeled terms are amplified above 100 bits.
    const nr::FriFormalMarginExperiment dual =
        nr::AssessFriFormalMarginExperiment(2, 96);
    BOOST_CHECK_GT(dual.proximity_bits_after_losses, 107.0);
    BOOST_CHECK_CLOSE(dual.field_domain_bits_after_losses, 220.0, 0.001);
    BOOST_CHECK_GT(dual.bottleneck_bits, 107.0);
    BOOST_CHECK(dual.parameter_target_met);
    BOOST_CHECK(!dual.formal_reduction_complete);
    BOOST_CHECK(!dual.authority_eligible);
}

BOOST_AUTO_TEST_CASE(
    dual_q96_bcs_nirop_repetition_remains_numeric_diagnostic)
{
    // FRI RBR Theorem 4.1's full field constant, rather than the old
    // |L|^2/|F| screen:
    //   log2((3.5)^7/(3*rho^(3/2))) = 17.0665 at rho=1/16.
    const nr::FriBcsRepetitionAssessment exact_batch =
        nr::AssessFriBcsRepetition(
            2, 96, 192, 24, 4, 3, 40, 28, 256, 1U << 14,
            nr::FriBatchingChallengeMode::IndependentCoefficients,
            8, 3, 256);
    BOOST_REQUIRE(exact_batch.fri_rbr_parameter_domain_valid);
    BOOST_CHECK_CLOSE(
        exact_batch.theorem_constant_loss_bits, 17.0665219537, 1e-7);
    BOOST_CHECK_CLOSE(
        exact_batch.field_rbr_bits, 126.9334780463, 1e-7);
    BOOST_CHECK_CLOSE(
        exact_batch.proximity_rbr_bits, 87.6035672400, 1e-7);
    BOOST_CHECK_CLOSE(
        exact_batch.lane_bcs_query_term_bits, 47.6035672400, 1e-7);
    BOOST_CHECK_CLOSE(
        exact_batch.lane_bcs_ro_collision_bits, 174.4150374993, 1e-7);

    // Lemma B.1 gives epsilon_rep(Q)<=epsilon_fs(Q)^2. Definition 2
    // measures log2(Q/epsilon_rep), hence Q's 40-bit work is added once
    // after the square. The 2^28 global-site union is then subtracted.
    BOOST_CHECK_CLOSE(
        exact_batch.global_work_bits, 107.2071344799, 1e-6);
    BOOST_CHECK_EQUAL(exact_batch.conservative_floor_bits, 107U);
    BOOST_CHECK(exact_batch.parameter_target_met);
    BOOST_CHECK_CLOSE(
        exact_batch.all_query_work_screen_bits, 72.6035672400, 1e-7);
    BOOST_CHECK_EQUAL(
        exact_batch.all_query_conservative_floor_bits, 72U);
    BOOST_CHECK(!exact_batch.all_query_parameter_target_met);
    BOOST_CHECK(exact_batch.published_batching_constant_exact);
    BOOST_CHECK(!exact_batch.batching_protocol_instantiation_proven);
    BOOST_CHECK(!exact_batch.batch_columns_manifest_derived);
    BOOST_CHECK(exact_batch.nirop_repetition_theorem_available);
    BOOST_CHECK(!exact_batch.executable_dual_lane_shape_present);
    BOOST_CHECK(!exact_batch.lane_statement_equality_enforced);
    BOOST_CHECK(!exact_batch.accept_all_lanes_enforced);
    BOOST_CHECK(!exact_batch.lane_domain_prefixes_present);
    BOOST_CHECK(!exact_batch.all_random_oracle_calls_lane_prefixed);
    BOOST_CHECK(
        !exact_batch.common_commitment_binding_quantitatively_accounted);
    BOOST_CHECK(!exact_batch.common_commitment_hybrid_reduction_complete);
    BOOST_CHECK_LT(exact_batch.legacy_modulo_bias_bits, 31.0);
    BOOST_CHECK_GT(exact_batch.uniform_limb_rejection_bits, 31.9);
    BOOST_CHECK_GT(
        exact_batch.uniform_sampler_exhaustion_bits_per_draw, 187.0);
    BOOST_CHECK_GT(
        exact_batch.uniform_sampler_global_completeness_bits, 150.0);
    BOOST_CHECK_GT(exact_batch.legacy_query_index_bias_bits, 63.9);
    BOOST_CHECK_EQUAL(
        exact_batch.manifest_challenge_draws_per_lane, 0U);
    BOOST_CHECK(!exact_batch.uniform_field_challenge_sampling_present);
    BOOST_CHECK(!exact_batch.uniform_sampler_draw_bound_manifest_derived);
    BOOST_CHECK(!exact_batch.power_of_two_query_domain_enforced);
    BOOST_CHECK(!exact_batch.uniform_query_index_sampling_present);
    BOOST_CHECK(!exact_batch.fixed_schedule_uniform_ood_sampling_present);
    BOOST_CHECK(!exact_batch.transcript_domains_proven_disjoint);
    BOOST_CHECK(!exact_batch.adversary_query_bound_enforced);
    BOOST_CHECK(!exact_batch.definition2_all_query_budgets_proven);
    BOOST_CHECK(!exact_batch.global_site_bound_manifest_derived);
    BOOST_CHECK(!exact_batch.formal_reduction_complete);
    BOOST_CHECK_EQUAL(exact_batch.certified_bits, 0U);
    BOOST_CHECK(!exact_batch.authority_eligible);
}

BOOST_AUTO_TEST_CASE(all_query_screen_q128_v5_is_executable_but_not_certified)
{
    const nr::FriBcsRepetitionAssessment dual_q128_independent =
        nr::AssessFriBcsRepetition(
            2, 128, 192, 24, 4, 3, 40, 28, 256, 1U << 14,
            nr::FriBatchingChallengeMode::IndependentCoefficients);
    BOOST_CHECK_CLOSE(
        dual_q128_independent.all_query_work_screen_bits,
        101.8047563200, 1e-7);
    BOOST_CHECK_EQUAL(
        dual_q128_independent.all_query_conservative_floor_bits, 101U);
    BOOST_CHECK(
        dual_q128_independent.all_query_parameter_target_met);
    BOOST_CHECK(
        dual_q128_independent.executable_dual_lane_shape_present);
    BOOST_CHECK(
        dual_q128_independent.uniform_field_challenge_sampling_present);
    BOOST_CHECK_EQUAL(
        dual_q128_independent.manifest_challenge_draws_per_lane,
        (1U << 14) + 26U);
    BOOST_CHECK(
        dual_q128_independent.uniform_sampler_draw_bound_manifest_derived);
    BOOST_CHECK(!dual_q128_independent.formal_reduction_complete);
    BOOST_CHECK_EQUAL(dual_q128_independent.certified_bits, 0U);

    // Keeping the current single-power RLC at the full 2^14 column cap makes
    // its modeled field term the all-Q bottleneck. Lemma 5.10 gives the exact
    // factor t-1, but applying it still requires a protocol-correspondence
    // proof and an executable manifest for the actual t.
    const nr::FriBcsRepetitionAssessment dual_q128_power =
        nr::AssessFriBcsRepetition(
            2, 128, 192, 24, 4, 3, 40, 28, 256, 1U << 14,
            nr::FriBatchingChallengeMode::SinglePowerChallenge);
    BOOST_CHECK_CLOSE(
        dual_q128_power.all_query_work_screen_bits,
        97.9335661041, 1e-7);
    BOOST_CHECK_EQUAL(
        dual_q128_power.all_query_conservative_floor_bits, 97U);
    BOOST_CHECK(!dual_q128_power.all_query_parameter_target_met);
    BOOST_CHECK(!dual_q128_power.authority_eligible);
}

BOOST_AUTO_TEST_CASE(
    dual_q128_hybrid_bound_composes_binding_and_fri_errors)
{
    BOOST_CHECK(
        !nr::AssessFriDualQ128HybridBound(0).parameters_valid);
    BOOST_CHECK(
        !nr::AssessFriDualQ128HybridBound(
             1, static_cast<nr::FriDualCommitmentTopology>(0xff))
             .parameters_valid);

    // At the old rounded 2^28 budget, quoting the 100-bit binding term by
    // itself is incorrect: unioning the 101.8048-bit FRI term lowers the
    // total to about 99.637 bits.
    const nr::FriDualQ128HybridBoundAssessment rounded_shared =
        nr::AssessFriDualQ128HybridBound(
            uint64_t{1} << 28,
            nr::FriDualCommitmentTopology::SharedMaster);
    BOOST_REQUIRE(rounded_shared.parameters_valid);
    BOOST_CHECK_CLOSE(
        rounded_shared.commitment_binding_bits, 100.0, 1e-9);
    BOOST_CHECK_CLOSE(
        rounded_shared.fri_all_query_bits, 101.8047563200, 1e-7);
    BOOST_CHECK_CLOSE(
        rounded_shared.composed_union_bits, 99.6368520489, 1e-7);
    BOOST_CHECK(!rounded_shared.numerical_target_met);

    const nr::FriDualQ128HybridBoundAssessment rounded_duplicated =
        nr::AssessFriDualQ128HybridBound(
            uint64_t{1} << 28,
            nr::FriDualCommitmentTopology::FullyDuplicatedLanes);
    BOOST_REQUIRE(rounded_duplicated.parameters_valid);
    BOOST_CHECK_CLOSE(
        rounded_duplicated.commitment_binding_bits, 99.0, 1e-9);
    BOOST_CHECK_CLOSE(
        rounded_duplicated.composed_union_bits, 98.8070298407, 1e-7);
    BOOST_CHECK(!rounded_duplicated.numerical_target_met);

    // The selected packed-four conditional manifest's site count is living
    // inventory (currently ~2^35.8). Derive every expected hybrid term from
    // that count + the Q128/V5 lane theorem; do NOT pin stale literals such as
    // "numerical_target_met == true" or "independence > 228" that silently
    // regress whenever the production proof-site manifest grows.
    const auto selected_manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    BOOST_REQUIRE(!selected_manifest.commitment.IsNull());
    BOOST_REQUIRE(
        selected_manifest.complete_global_upper_bound_manifest_derived);
    BOOST_REQUIRE_GT(selected_manifest.total_proof_sites, 0U);

    const double expected_site_log2 = std::log2(
        static_cast<double>(selected_manifest.total_proof_sites));
    const nr::FriBcsRepetitionAssessment exact_fri =
        nr::AssessFriBcsRepetition(
            2, 128, 192, 24, 4, 3, 40, 0, 256, 1U << 14,
            nr::FriBatchingChallengeMode::IndependentCoefficients);
    BOOST_REQUIRE(exact_fri.fri_rbr_parameter_domain_valid);
    const double expected_fri_all_query_bits = std::min(
        exact_fri.all_query_rbr_branch_work_bits -
            expected_site_log2 / 2.0,
        exact_fri.all_query_ro_branch_work_bits -
            expected_site_log2 / 4.0);
    const auto composed_union_of = [](double a, double b) {
        const double smaller = std::min(a, b);
        const double larger = std::max(a, b);
        return smaller - std::log2(1.0 + std::exp2(smaller - larger));
    };

    const nr::FriDualQ128HybridBoundAssessment exact_shared =
        nr::AssessFriDualQ128HybridBound(
            selected_manifest.total_proof_sites,
            nr::FriDualCommitmentTopology::SharedMaster);
    BOOST_REQUIRE(exact_shared.parameters_valid);
    const double expected_shared_binding_bits =
        static_cast<double>(rcx::kRCFri3AlgDualAlgHashCollisionBits) -
        expected_site_log2;
    const double expected_shared_union = composed_union_of(
        expected_fri_all_query_bits, expected_shared_binding_bits);
    BOOST_CHECK_CLOSE(
        exact_shared.global_site_log2, expected_site_log2, 1e-9);
    BOOST_CHECK_CLOSE(
        exact_shared.fri_all_query_bits, expected_fri_all_query_bits,
        1e-9);
    BOOST_CHECK_CLOSE(
        exact_shared.commitment_binding_bits,
        expected_shared_binding_bits, 1e-9);
    BOOST_CHECK_CLOSE(
        exact_shared.composed_union_bits, expected_shared_union, 1e-9);
    BOOST_CHECK_EQUAL(
        exact_shared.numerical_target_met,
        expected_shared_union >=
            static_cast<double>(nr::kNarrowTargetSoundnessBits));
    BOOST_CHECK(!exact_shared.exact_site_manifest_backend_enforced);
    BOOST_CHECK(!exact_shared.commitment_hybrid_reduction_complete);
    BOOST_CHECK(!exact_shared.formal_reduction_complete);
    BOOST_CHECK(!exact_shared.authority_eligible);

    const nr::FriDualQ128HybridBoundAssessment exact_duplicated =
        nr::AssessFriDualQ128HybridBound(
            selected_manifest.total_proof_sites,
            nr::FriDualCommitmentTopology::FullyDuplicatedLanes);
    BOOST_REQUIRE(exact_duplicated.parameters_valid);
    const double expected_duplicated_binding_bits =
        static_cast<double>(rcx::kRCFri3AlgDualAlgHashCollisionBits) -
        expected_site_log2 - std::log2(2.0);
    const double expected_duplicated_union = composed_union_of(
        expected_fri_all_query_bits, expected_duplicated_binding_bits);
    BOOST_CHECK_CLOSE(
        exact_duplicated.composed_union_bits,
        expected_duplicated_union, 1e-9);
    BOOST_CHECK_EQUAL(
        exact_duplicated.numerical_target_met,
        expected_duplicated_union >=
            static_cast<double>(nr::kNarrowTargetSoundnessBits));
    BOOST_CHECK(!exact_duplicated.authority_eligible);

    // Two common domain-separated roots do not amplify binding merely because
    // their tags differ.  Conservatively they have the same two-event screen
    // as duplicated lane roots.  The much larger simultaneous-collision
    // exponent is reported only to quantify the prize if an independence
    // reduction and executable ordered-pair transcript are later supplied.
    const nr::FriDualQ128HybridBoundAssessment two_common =
        nr::AssessFriDualQ128HybridBound(
            selected_manifest.total_proof_sites,
            nr::FriDualCommitmentTopology::TwoCommonRoots);
    BOOST_REQUIRE(two_common.parameters_valid);
    BOOST_CHECK_CLOSE(
        two_common.commitment_binding_bits,
        exact_duplicated.commitment_binding_bits, 1e-9);
    BOOST_CHECK_CLOSE(
        two_common.composed_union_bits,
        exact_duplicated.composed_union_bits, 1e-9);
    const double expected_independence_amplified =
        2.0 *
            static_cast<double>(rcx::kRCFri3AlgDualAlgHashCollisionBits) -
        expected_site_log2;
    BOOST_CHECK_CLOSE(
        two_common.independence_amplified_binding_bits,
        expected_independence_amplified, 1e-9);
    BOOST_CHECK_EQUAL(
        two_common.numerical_target_met,
        expected_duplicated_union >=
            static_cast<double>(nr::kNarrowTargetSoundnessBits));
    BOOST_CHECK(!two_common.two_common_root_backend_executable);
    BOOST_CHECK(!two_common.binding_independence_reduction_complete);
    BOOST_CHECK(!two_common.authority_eligible);
    BOOST_CHECK_EQUAL(
        two_common.note,
        "narrow_vcs:hybrid_bound:two_common_roots_independence_open");
}

BOOST_AUTO_TEST_CASE(default_q128_v5_independent_batching_is_fail_closed)
{
    // V5 executes independent Fp3 coefficients, so the Lemma-5.10 (t-1)
    // one-power loss does not apply. Protocol correspondence, manifest width,
    // shared-commitment binding and full NIROP separation remain open.
    const nr::FriBcsRepetitionAssessment current =
        nr::AssessFriBcsRepetition();
    BOOST_CHECK(
        current.batching_mode ==
        nr::FriBatchingChallengeMode::IndependentCoefficients);
    BOOST_CHECK_CLOSE(
        current.batching_loss_bits, 0.0, 1e-7);
    BOOST_CHECK_CLOSE(current.field_rbr_bits, 126.9334780463, 1e-7);
    BOOST_CHECK_GT(current.global_work_bits, 165.0);
    BOOST_CHECK_EQUAL(current.conservative_floor_bits, 165U);
    BOOST_CHECK(current.parameter_target_met);
    BOOST_CHECK_EQUAL(current.all_query_conservative_floor_bits, 101U);
    BOOST_CHECK(current.all_query_parameter_target_met);
    BOOST_CHECK(current.published_batching_constant_exact);
    BOOST_CHECK(current.executable_dual_lane_shape_present);
    BOOST_CHECK_EQUAL(
        current.manifest_challenge_draws_per_lane,
        (1U << 14) + 26U);
    BOOST_CHECK(current.uniform_sampler_draw_bound_manifest_derived);
    BOOST_CHECK(!current.batching_protocol_instantiation_proven);
    BOOST_CHECK(!current.batch_columns_manifest_derived);
    BOOST_CHECK(!current.formal_reduction_complete);
    BOOST_CHECK_EQUAL(current.certified_bits, 0U);
    BOOST_CHECK(!current.authority_eligible);
    BOOST_CHECK_EQUAL(
        current.note,
        "narrow_vcs:bcs_repetition:batch_protocol_instantiation_open");
}

BOOST_AUTO_TEST_CASE(single_q192_lane_misses_full_provable_work_target)
{
    const nr::FriBcsRepetitionAssessment single =
        nr::AssessFriBcsRepetition(
            1, 192, 192, 24, 4, 3, 40, 28, 256, 1,
            nr::FriBatchingChallengeMode::IndependentCoefficients);
    BOOST_CHECK_CLOSE(single.field_rbr_bits, 126.9334780463, 1e-7);
    BOOST_CHECK_LT(single.global_work_bits, 99.0);
    BOOST_CHECK_EQUAL(single.conservative_floor_bits, 98U);
    BOOST_CHECK(!single.parameter_target_met);
    BOOST_CHECK_EQUAL(single.certified_bits, 0U);
    BOOST_CHECK(!single.authority_eligible);
}

BOOST_AUTO_TEST_CASE(decomposed_parallel_binary_lane_closes_q148_recursive_lde)
{
    nr::NarrowVcsConfig config;
    config.poseidon_strategy = nr::PoseidonLaneStrategy::DecomposedX2X4;
    config.child_packing = nr::ChildPacking::ParallelLanes;
    nr::NarrowChildShape shape = nr::ProductionEpisodeChildShape();
    shape.queries = 148;
    const nr::NarrowVcsPlan leaf = nr::BuildNarrowVcsPlan(shape, config);
    BOOST_REQUIRE_MESSAGE(leaf.valid, leaf.note);
    const nr::NarrowVcsPlan level1 =
        nr::BuildNarrowVcsPlan(nr::NextRecursiveChildShape(leaf), config);
    BOOST_REQUIRE_MESSAGE(level1.valid, level1.note);
    const nr::NarrowVcsPlan level2 =
        nr::BuildNarrowVcsPlan(nr::NextRecursiveChildShape(level1), config);
    BOOST_REQUIRE_MESSAGE(level2.valid, level2.note);

    BOOST_CHECK_EQUAL(leaf.parent_width, 856U);
    BOOST_CHECK_EQUAL(level1.parent_width, 856U);
    BOOST_CHECK_EQUAL(level2.parent_width, 856U);
    BOOST_CHECK_EQUAL(leaf.max_algebraic_degree, 4U);
    BOOST_CHECK_EQUAL(leaf.trace_rows, 1U << 17);
    BOOST_CHECK_EQUAL(leaf.n_lde, 1U << 23);
    BOOST_CHECK_EQUAL(level1.active_rows, 177187U);
    BOOST_CHECK_EQUAL(level1.trace_rows, 1U << 18);
    BOOST_CHECK_EQUAL(level1.n_lde, 1U << 24);
    BOOST_CHECK_EQUAL(level2.active_rows, 184884U);
    BOOST_CHECK_EQUAL(level2.trace_rows, 1U << 18);
    BOOST_CHECK_EQUAL(level2.n_lde, 1U << 24);
    BOOST_CHECK(level1.backend_lde_supported);
    BOOST_CHECK(level2.backend_lde_supported);

    const nr::NarrowVcsReadiness readiness =
        nr::AssessNarrowVcsReadiness(leaf);
    BOOST_CHECK(readiness.width_fixed_point);
    BOOST_CHECK(readiness.trace_shape_fixed_point);
    BOOST_CHECK(readiness.backend_shape_supported);
    BOOST_CHECK(!readiness.implementation_complete);
    BOOST_CHECK(!readiness.production_ready);
}

BOOST_AUTO_TEST_CASE(decomposed_fixed_point_closes_minimum_soundness_query_shapes)
{
    nr::NarrowVcsConfig config;
    config.poseidon_strategy = nr::PoseidonLaneStrategy::DecomposedX2X4;
    config.child_packing = nr::ChildPacking::ParallelLanes;
    auto check_shape = [&](uint32_t queries, uint64_t level1_active,
                           uint64_t level2_active) {
        nr::NarrowChildShape shape = nr::ProductionEpisodeChildShape();
        shape.queries = queries;
        const nr::NarrowVcsPlan leaf = nr::BuildNarrowVcsPlan(shape, config);
        BOOST_REQUIRE(leaf.valid);
        const nr::NarrowVcsPlan level1 =
            nr::BuildNarrowVcsPlan(nr::NextRecursiveChildShape(leaf), config);
        BOOST_REQUIRE(level1.valid);
        const nr::NarrowVcsPlan level2 =
            nr::BuildNarrowVcsPlan(nr::NextRecursiveChildShape(level1), config);
        BOOST_REQUIRE(level2.valid);
        BOOST_CHECK_EQUAL(leaf.parent_width, 856U);
        BOOST_CHECK_EQUAL(level1.active_rows, level1_active);
        BOOST_CHECK_EQUAL(level2.active_rows, level2_active);
        BOOST_CHECK_EQUAL(level1.trace_rows, 1U << 18);
        BOOST_CHECK_EQUAL(level2.trace_rows, 1U << 18);
        BOOST_CHECK_EQUAL(level1.n_lde, 1U << 24);
        BOOST_CHECK_EQUAL(level2.n_lde, 1U << 24);
        BOOST_CHECK(level1.backend_lde_supported);
        BOOST_CHECK(level2.backend_lde_supported);
    };
    check_shape(154, 184339U, 192348U); // unified root, raw >=100
    check_shape(159, 190299U, 198568U); // 14 roots, >=100 after union
}

BOOST_AUTO_TEST_CASE(degree_reduction_without_parallel_binary_lane_is_insufficient)
{
    nr::NarrowVcsConfig config;
    config.poseidon_strategy = nr::PoseidonLaneStrategy::DecomposedX2X4;
    config.child_packing = nr::ChildPacking::VerticalRows;
    nr::NarrowChildShape shape = nr::ProductionEpisodeChildShape();
    shape.queries = 148;
    const nr::NarrowVcsPlan leaf = nr::BuildNarrowVcsPlan(shape, config);
    BOOST_REQUIRE(leaf.valid);
    const nr::NarrowVcsPlan level1 =
        nr::BuildNarrowVcsPlan(nr::NextRecursiveChildShape(leaf), config);
    BOOST_REQUIRE(level1.valid);
    BOOST_CHECK_EQUAL(leaf.parent_width, 428U);
    BOOST_CHECK_EQUAL(level1.trace_rows, 1U << 19);
    BOOST_CHECK_EQUAL(level1.n_lde, 1U << 25);
    BOOST_CHECK(!level1.backend_lde_supported);
}

BOOST_AUTO_TEST_CASE(fully_quadratic_vertical_lane_closes_q148_recursive_lde)
{
    nr::NarrowVcsConfig config;
    config.poseidon_strategy = nr::PoseidonLaneStrategy::DecomposedX2X4X6;
    config.child_packing = nr::ChildPacking::VerticalRows;
    nr::NarrowChildShape shape = nr::ProductionEpisodeChildShape();
    shape.queries = 148;
    const nr::NarrowVcsPlan leaf = nr::BuildNarrowVcsPlan(shape, config);
    BOOST_REQUIRE_MESSAGE(leaf.valid, leaf.note);
    const nr::NarrowVcsPlan level1 =
        nr::BuildNarrowVcsPlan(nr::NextRecursiveChildShape(leaf), config);
    BOOST_REQUIRE_MESSAGE(level1.valid, level1.note);
    const nr::NarrowVcsPlan level2 =
        nr::BuildNarrowVcsPlan(nr::NextRecursiveChildShape(level1), config);
    BOOST_REQUIRE_MESSAGE(level2.valid, level2.note);

    BOOST_CHECK_EQUAL(leaf.parent_width, 546U);
    BOOST_CHECK_EQUAL(level1.parent_width, 546U);
    BOOST_CHECK_EQUAL(level2.parent_width, 546U);
    BOOST_CHECK_EQUAL(leaf.max_algebraic_degree, 3U);
    BOOST_CHECK_EQUAL(leaf.trace_rows, 1U << 18);
    BOOST_CHECK_EQUAL(leaf.n_lde, 1U << 23);
    BOOST_CHECK_EQUAL(level1.active_rows, 320976U);
    BOOST_CHECK_EQUAL(level1.trace_rows, 1U << 19);
    BOOST_CHECK_EQUAL(level1.n_lde, 1U << 24);
    BOOST_CHECK_EQUAL(level2.active_rows, 336368U);
    BOOST_CHECK_EQUAL(level2.trace_rows, 1U << 19);
    BOOST_CHECK_EQUAL(level2.n_lde, 1U << 24);
    BOOST_CHECK(level1.backend_lde_supported);
    BOOST_CHECK(level2.backend_lde_supported);
    const nr::NarrowVcsReadiness readiness =
        nr::AssessNarrowVcsReadiness(leaf);
    BOOST_CHECK(readiness.width_fixed_point);
    BOOST_CHECK(readiness.trace_shape_fixed_point);
    BOOST_CHECK(readiness.backend_shape_supported);
    BOOST_CHECK(!readiness.implementation_complete);
    BOOST_CHECK(!readiness.production_ready);
}

BOOST_AUTO_TEST_CASE(fully_quadratic_vertical_lane_closes_soundness_query_shapes)
{
    nr::NarrowVcsConfig config;
    config.poseidon_strategy = nr::PoseidonLaneStrategy::DecomposedX2X4X6;
    config.child_packing = nr::ChildPacking::VerticalRows;
    auto check_shape = [&](uint32_t queries, uint64_t level1_active,
                           uint64_t level2_active) {
        nr::NarrowChildShape shape = nr::ProductionEpisodeChildShape();
        shape.queries = queries;
        const nr::NarrowVcsPlan leaf = nr::BuildNarrowVcsPlan(shape, config);
        BOOST_REQUIRE(leaf.valid);
        const nr::NarrowVcsPlan level1 =
            nr::BuildNarrowVcsPlan(nr::NextRecursiveChildShape(leaf), config);
        BOOST_REQUIRE(level1.valid);
        const nr::NarrowVcsPlan level2 =
            nr::BuildNarrowVcsPlan(nr::NextRecursiveChildShape(level1), config);
        BOOST_REQUIRE(level2.valid);
        BOOST_CHECK_EQUAL(leaf.parent_width, 546U);
        BOOST_CHECK_EQUAL(level1.active_rows, level1_active);
        BOOST_CHECK_EQUAL(level2.active_rows, level2_active);
        BOOST_CHECK_EQUAL(level1.trace_rows, 1U << 19);
        BOOST_CHECK_EQUAL(level2.trace_rows, 1U << 19);
        BOOST_CHECK_EQUAL(level1.n_lde, 1U << 24);
        BOOST_CHECK_EQUAL(level2.n_lde, 1U << 24);
        BOOST_CHECK(level1.backend_lde_supported);
        BOOST_CHECK(level2.backend_lde_supported);
    };
    check_shape(154, 333948U, 349964U);
    check_shape(159, 344758U, 361294U);
    check_shape(160, 346920U, 363560U);
    check_shape(192, 416104U, 436072U);
}

BOOST_AUTO_TEST_CASE(malformed_shapes_fail_before_counting)
{
    nr::NarrowChildShape bad = nr::ProductionEpisodeChildShape();
    bad.child_n_lde >>= 1;
    const nr::NarrowVcsPlan p = nr::BuildNarrowVcsPlan(bad);
    BOOST_CHECK(!p.valid);
    BOOST_CHECK(!p.note.empty());
}

// ===========================================================================
// REAL-CHILD NARROW RECURSION.
//
// narrow_recurse itself is a planner: it owns no AIR and no witness builder,
// so kNarrowVcsExecutable stays false.  The EXECUTABLE narrow V_CS that the
// planner describes ("one hash permutation per lane per row, transcript
// values streamed") is recursive_fixedpoint's vertical hash-opening chip plus
// its fold/scalar memory bus (kHashOpeningAirExecutable == true).  The cases
// below drive REAL role-child proofs through that construction, prove the
// narrow parent with the production prover, verify it with the real
// unmodified verifier, and measure the serialized parent proof.
//
// Every reject below is decided by the FRI/AIR prover-verifier pair
// (division_exact / AirQuotientVerify*), never by a witness-violation count.
// ===========================================================================
namespace {

using NarrowAlgB3 = aq::AirFriBackendAlg<gfx::Fp3>;

uint256 NarrowSeed(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

struct RealRoleChild {
    aq::AirConstraintSystem<gfx::Fp3> cs;
    fpx::AlgAirProof proof;
    uint256 seed;
    std::string tag;
};

/** Prove a real role C_rho with the production prover and require the real
 *  unmodified verifier to accept it. */
RealRoleChild ProveRealRoleChild(
    const char* tag,
    const aq::AirConstraintSystem<gfx::Fp3>& cs,
    const std::vector<std::vector<gfx::Fp3>>& witness,
    const uint256& seed)
{
    RealRoleChild out;
    out.tag = tag;
    out.cs = cs;
    out.seed = seed;
    BOOST_REQUIRE_EQUAL(
        ar::CountWitnessViolationsOnH(cs, witness), 0U);
    const auto proved =
        aq::AirQuotientProve<gfx::Fp3, NarrowAlgB3>(
            cs, witness, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok && proved.division_exact,
                          proved.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        (aq::AirQuotientVerify<gfx::Fp3, NarrowAlgB3>(
            cs, proved.proof, seed, &why)),
        why);
    out.proof = proved.proof;
    return out;
}

/** The real Stage-3 episode header/target role: 2 columns, 32 rows, compact
 *  byte equality against a consensus-resolved nBits target. */
RealRoleChild RealHeaderTargetChild(unsigned char header_byte = 0x71)
{
    rcx::RCStage3SuccinctProof statement;
    statement.statement = rcx::RCStage3StatementKind::Episode;
    statement.public_inputs.height = 23;
    statement.public_inputs.n_bits = 0x1d00ffffU;
    statement.public_inputs.episode_profile = 2;
    statement.public_inputs.transcript_version = rcx::ENC_RC_V4;
    statement.public_inputs.header_commitment = NarrowSeed(header_byte);
    statement.public_inputs.params_commitment = NarrowSeed(0x72);
    statement.public_inputs.sigma = NarrowSeed(0x73);
    statement.public_inputs.episode_digest = NarrowSeed(0x74);
    statement.public_inputs.target.SetNull();
    statement.public_inputs.target.data()[26] = 0xff;
    statement.public_inputs.target.data()[27] = 0xff;

    rcx::RCStage3EpisodeHeaderTargetPin pin;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rcx::BuildRCStage3EpisodeHeaderTargetPin(statement, pin, &why),
        why);
    aq::AirConstraintSystem<gfx::Fp3> cs;
    BOOST_REQUIRE_MESSAGE(
        rcx::BuildRCStage3EpisodeHeaderTargetConstraintSystem(
            pin, cs, &why),
        why);
    cs.preprocessed_pin_ood = true;
    std::vector<std::vector<gfx::Fp3>> columns(
        cs.n_columns,
        std::vector<gfx::Fp3>(cs.n_rows, gfx::Fp3::Zero()));
    for (const auto& [column, values] : cs.preprocessed) {
        columns[column] = values;
    }
    columns[rcx::kRCStage3EpisodeHeaderTargetByte] =
        columns[rcx::kRCStage3EpisodeHeaderTargetExpectedByte];
    return ProveRealRoleChild(
        "EpisodeHeaderTarget", cs, columns,
        rcx::ComputeRCStage3EpisodeHeaderTargetSeed(pin));
}

/** Exact serialized size of one narrow parent proof: the alg batch codec plus
 *  the row-wise trace commitment and the per-query next/trace openings. */
template <typename Openings>
uint64_t MeasuredNarrowParentProofBytes(
    const rcx::Fri3AlgBatchProof& batch,
    const Openings& next_openings,
    uint64_t* batch_bytes_out)
{
    std::vector<unsigned char> encoded;
    const size_t batch_bytes =
        rcx::SerializeFri3AlgBatchProof(batch, encoded);
    BOOST_REQUIRE_EQUAL(batch_bytes, encoded.size());
    BOOST_REQUIRE_NE(batch_bytes, 0U);
    if (batch_bytes_out != nullptr) *batch_bytes_out = batch_bytes;
    uint64_t total = uint64_t{batch_bytes} + 32 + 4;
    for (const auto& paths : next_openings) {
        total += 4;
        for (const auto& path : paths) {
            total += 8;
            total += uint64_t{path.values.size()} * 3 * sizeof(uint64_t);
            total += uint64_t{path.siblings.size()} *
                     rcx::alg_hash::kAlgHashDigestLen * sizeof(uint64_t);
        }
    }
    return total;
}

/** Cells the parent's own batched-FRI LDE would materialize. */
uint64_t NarrowParentLdeCells(
    const aq::AirConstraintSystem<gfx::Fp3>& cs)
{
    uint32_t max_degree = 1;
    for (const auto& constraint : cs.constraints) {
        max_degree = std::max(max_degree, constraint.alg_degree);
    }
    const uint64_t quotient_len =
        uint64_t{max_degree > 1 ? max_degree - 1 : 1} *
        (uint64_t{cs.n_rows} - 1);
    uint64_t n_coeffs = 1;
    while (n_coeffs < std::max<uint64_t>(cs.n_rows, quotient_len)) {
        n_coeffs <<= 1;
    }
    return uint64_t{cs.n_columns} * n_coeffs * rcx::kRCFriBlowup;
}

} // namespace

// The planner's own executability gate is a statement about narrow_recurse,
// not about the whole repository: narrow_recurse contains no AirConstraint
// callbacks and no witness builder, so it must stay false.  The executable
// narrow construction lives in recursive_fixedpoint and is asserted here so
// that the two facts are recorded together and cannot drift apart.
BOOST_AUTO_TEST_CASE(narrow_planner_is_not_the_executable_narrow_vcs)
{
    static_assert(!nr::kNarrowVcsExecutable);
    static_assert(!nr::kNarrowVcsProductionReady);
    static_assert(fpx::kHashOpeningAirExecutable);
    static_assert(fpx::kFoldHashScalarMemoryBusExecutable);
    static_assert(!fpx::kCompleteRecursiveFixedPointExecutable);
    static_assert(!fpx::kRecursiveFixedPointConsensusAuthority);

    // The planner's fully-quadratic vertical lane and the executable chip
    // agree on the per-lane Poseidon decomposition (130 permutation cells and
    // three 118-cell S-box auxiliary banks).
    const nr::NarrowLaneLayout lane = nr::CanonicalNarrowLaneLayout(
        nr::PoseidonLaneStrategy::DecomposedX2X4X6);
    BOOST_CHECK_EQUAL(lane.permutation.count, 130U);
    BOOST_CHECK_EQUAL(lane.sbox_x2.count, 118U);
    BOOST_CHECK_EQUAL(lane.sbox_x4.count, 118U);
    BOOST_CHECK_EQUAL(lane.sbox_x6.count, 118U);
    const auto executable = fpx::CanonicalHashOpeningLayout();
    BOOST_CHECK_LT(executable.End(), 1024U);
}

// ---------------------------------------------------------------------------
// EXPANSION FACTOR.  The dense arity-4 V_CS costs ~677.5 parent columns per
// child column (measured elsewhere), so a parent can never be a child. The
// vertical narrow lane is the claimed escape: it must cost ZERO parent columns
// per child column and pay in rows instead. This case measures that directly
// on REAL role children whose widths differ by two orders of magnitude, using
// the proof-independent scheduler so no wide witness is materialized.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(
    narrow_vcs_width_is_constant_in_child_width_on_real_children)
{
    struct Point {
        std::string tag;
        uint32_t child_w{0};
        uint32_t vcs_columns{0};
        uint32_t vcs_rows{0};
        uint64_t active_rows{0};
    };
    std::vector<Point> points;

    const auto measure = [&points](const RealRoleChild& child) {
        const ar::ChildPublicInputs pi =
            ar::ExtractChildPublicInputs(child.cs, child.proof, child.seed);
        const fpx::HashOpeningProgram schedule =
            fpx::BuildHashOpeningProgram(pi);
        BOOST_REQUIRE_MESSAGE(schedule.valid, schedule.note);
        aq::AirConstraintSystem<gfx::Fp3> lane_cs;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            fpx::BuildHashOpeningConstraintSystem(schedule, lane_cs, &why),
            why);
        points.push_back({child.tag, pi.child_w, lane_cs.n_columns,
                          lane_cs.n_rows, schedule.active_rows});
    };

    measure(RealHeaderTargetChild());
    {
        const auto product =
            matmul::v4::rc::BuildRCStage3CoupledPermutationRoleAir(
                gfx::Fp3::FromFp(gfx::FromU64(0x2bad10ULL)), 0, 3, nullptr);
        BOOST_REQUIRE_MESSAGE(product.ok, product.note);
        measure(ProveRealRoleChild(
            "CoupledPermutation", product.cs, product.witness,
            NarrowSeed(0x5a)));
    }

    BOOST_REQUIRE_EQUAL(points.size(), 2U);
    for (const Point& point : points) {
        BOOST_TEST_MESSAGE(
            "NARROW_WIDTH child=" << point.tag
            << " child_w=" << point.child_w
            << " narrow_vcs_columns=" << point.vcs_columns
            << " narrow_vcs_rows=" << point.vcs_rows
            << " narrow_active_rows=" << point.active_rows);
    }
    BOOST_REQUIRE_GT(points[1].child_w, points[0].child_w * 50U);
    // The load-bearing claim: the narrow V_CS column count does not move at
    // all when the child width grows by two orders of magnitude.
    BOOST_CHECK_EQUAL(points[0].vcs_columns, points[1].vcs_columns);
    BOOST_CHECK_EQUAL(
        points[0].vcs_columns,
        fpx::CanonicalHashOpeningLayout().End());
    // ... and the cost is paid in rows.
    BOOST_CHECK_GT(points[1].active_rows, points[0].active_rows);
    BOOST_CHECK_LE(points[0].vcs_columns,
                   matmul::v4::rc::kRCFri3AlgBatchMaxColumns);
}

BOOST_AUTO_TEST_CASE(
    narrow_parent_consumes_real_role_child_and_fri_round_trips)
{
    const RealRoleChild child = RealHeaderTargetChild();

    fpx::FoldBusComposition parent =
        fpx::BuildFoldBusComposition(child.cs, child.proof, child.seed);
    BOOST_REQUIRE_MESSAGE(parent.valid, parent.note);
    BOOST_REQUIRE(parent.hash.proof_derived);
    BOOST_REQUIRE(parent.hash.native_child_accepted);
    BOOST_CHECK_EQUAL(parent.violations, 0U);
    BOOST_CHECK_EQUAL(parent.columns.size(), parent.combined.n_columns);
    // Bounded width: the narrow parent does NOT scale its column count with
    // the child proof; the child is streamed through rows.
    BOOST_CHECK_LT(parent.combined.n_columns, 1024U);

    const uint64_t lde_cells = NarrowParentLdeCells(parent.combined);
    BOOST_TEST_MESSAGE(
        "NARROW_REAL_CHILD child=" << child.tag
        << " child_cols=" << child.cs.n_columns
        << " child_rows=" << child.cs.n_rows
        << " child_queries=" << child.proof.batch.queries.size()
        << " parent_rows=" << parent.combined.n_rows
        << " parent_cols=" << parent.combined.n_columns
        << " parent_constraints=" << parent.combined.constraints.size()
        << " parent_lde_cells=" << lde_cells);

    const uint256 parent_seed = NarrowSeed(0x91);
    const auto prove_start = std::chrono::steady_clock::now();
    const auto proved = aq::AirQuotientProveRows(
        parent.combined, parent.columns, parent_seed, {});
    const uint64_t prove_micros =
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - prove_start)
                .count());
    BOOST_REQUIRE_MESSAGE(proved.ok && proved.division_exact, proved.note);

    std::string why;
    const auto verify_start = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRows(
            parent.combined, proved.proof, parent_seed, &why),
        why);
    const uint64_t verify_micros =
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - verify_start)
                .count());

    // The same proof container, handed to the ordinary recursion-backend
    // verifier that a parent's own consumer would run.
    fpx::AlgAirProof ordinary;
    ordinary.batch = proved.proof.batch;
    ordinary.next_openings = proved.proof.next_openings;
    ordinary.trace_commit = proved.proof.trace_commit;
    BOOST_REQUIRE_MESSAGE(
        (aq::AirQuotientVerify<gfx::Fp3, NarrowAlgB3>(
            parent.combined, ordinary, parent_seed, &why)),
        why);

    uint64_t batch_bytes = 0;
    const uint64_t proof_bytes = MeasuredNarrowParentProofBytes(
        proved.proof.batch, proved.proof.next_openings, &batch_bytes);
    BOOST_CHECK_LE(batch_bytes, rcx::kRCFriMaxProofBytesHard);
    BOOST_TEST_MESSAGE(
        "NARROW_REAL_CHILD_PROOF child=" << child.tag
        << " queries=" << proved.proof.batch.queries.size()
        << " prove_us=" << prove_micros
        << " verify_us=" << verify_micros
        << " batch_bytes=" << batch_bytes
        << " total_proof_bytes=" << proof_bytes);

    // -----------------------------------------------------------------------
    // SHAPE FIXED POINT, level 1 -> level 2, on the parent's OWN real proof.
    // The dense arity-4 V_CS fails here: a parent's proof cannot be a child
    // because the V_CS width is ~677.5x the child width. Re-enter the narrow
    // parent's own proof and measure what the next level's V_CS looks like.
    // -----------------------------------------------------------------------
    const ar::ChildPublicInputs level2_pi =
        ar::ExtractChildPublicInputs(parent.combined, ordinary, parent_seed);
    const fpx::HashOpeningProgram level2 =
        fpx::BuildHashOpeningProgram(level2_pi);
    BOOST_REQUIRE_MESSAGE(level2.valid, level2.note);
    aq::AirConstraintSystem<gfx::Fp3> level2_cs;
    BOOST_REQUIRE_MESSAGE(
        fpx::BuildHashOpeningConstraintSystem(level2, level2_cs, &why), why);
    BOOST_TEST_MESSAGE(
        "NARROW_FIXED_POINT level=2 (from the level-1 parent's OWN proof)"
        << " child_w=" << level2_pi.child_w
        << " child_rows=" << level2_pi.child_n_rows
        << " child_n_coeffs=" << level2_pi.child_n_coeffs
        << " child_n_lde=" << level2_pi.child_n_lde
        << " merkle_depth=" << level2_pi.merkle_depth
        << " n_folds=" << level2_pi.n_folds
        << " vcs_columns=" << level2_cs.n_columns
        << " vcs_rows=" << level2_cs.n_rows
        << " active_rows=" << level2.active_rows);
    // Width fixed point: consuming a 574-column narrow parent costs the SAME
    // number of V_CS columns as consuming a 2-column leaf child.
    BOOST_CHECK_EQUAL(level2_cs.n_columns,
                      fpx::CanonicalHashOpeningLayout().End());
    BOOST_CHECK_LE(level2_cs.n_columns,
                   matmul::v4::rc::kRCFri3AlgBatchMaxColumns);
    BOOST_CHECK_LE(uint64_t{level2_pi.child_n_lde},
                   uint64_t{1} << matmul::v4::rc::kRCFriMaxLdeLog2);
}

// ---------------------------------------------------------------------------
// SHAPE FIXED-POINT ITERATION.  Level 1 is MEASURED from a real role child.
// Levels 2..N are COMPUTED by re-running the real, proof-independent
// hash-opening scheduler on the previous level's shape. The narrow V_CS width
// is constant, so the only question is whether the ROW count converges.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(narrow_recursion_shape_fixed_point_iteration)
{
    const RealRoleChild child = RealHeaderTargetChild();
    ar::ChildPublicInputs pi =
        ar::ExtractChildPublicInputs(child.cs, child.proof, child.seed);
    const uint32_t queries =
        static_cast<uint32_t>(child.proof.batch.queries.size());

    // Composed narrow parent width and maximum algebraic degree, MEASURED once
    // on the real level-1 parent (hash lane + fold/scalar/DEEP buses).
    fpx::FoldBusComposition level1 =
        fpx::BuildFoldBusComposition(child.cs, child.proof, child.seed);
    BOOST_REQUIRE_MESSAGE(level1.valid, level1.note);
    const uint32_t narrow_width = level1.combined.n_columns;
    uint32_t narrow_max_degree = 1;
    for (const auto& constraint : level1.combined.constraints) {
        narrow_max_degree = std::max(narrow_max_degree, constraint.alg_degree);
    }
    const uint32_t bus_column_overhead =
        narrow_width - fpx::CanonicalHashOpeningLayout().End();
    BOOST_TEST_MESSAGE(
        "NARROW_ITER level=1 MEASURED child_w=" << pi.child_w
        << " narrow_width=" << narrow_width
        << " hash_lane_width=" << fpx::CanonicalHashOpeningLayout().End()
        << " bus_overhead=" << bus_column_overhead
        << " narrow_rows=" << level1.combined.n_rows
        << " narrow_max_degree=" << narrow_max_degree
        << " queries=" << queries);
    // Release both retained copies of the large witness explicitly.
    // AppleClang correctly rejects aggregate value-initialization here because
    // FoldBusComposition contains FoldBusLayout, whose defaulted-argument
    // constructor is explicit.
    decltype(level1.columns){}.swap(level1.columns);
    decltype(level1.hash.columns){}.swap(level1.hash.columns);

    const auto log2_exact = [](uint64_t n) {
        uint32_t out = 0;
        while (n > 1) { n >>= 1; ++out; }
        return out;
    };
    const auto next_pow2 = [](uint64_t n) {
        uint64_t out = 1;
        while (out < n) out <<= 1;
        return out;
    };

    // Advance the shape by one narrow recursion level. `arity` children are
    // streamed vertically into one parent, so arity multiplies rows and never
    // columns.
    const auto advance = [&](uint32_t vcs_rows, uint32_t queries_per_node) {
        ar::ChildPublicInputs out = pi;
        out.child_w = narrow_width;
        out.child_n_rows = vcs_rows;
        out.child_quotient_len = static_cast<uint32_t>(
            uint64_t{narrow_max_degree - 1} * (uint64_t{vcs_rows} - 1));
        out.child_n_coeffs = static_cast<uint32_t>(next_pow2(
            std::max<uint64_t>(vcs_rows, out.child_quotient_len)));
        out.child_n_lde = out.child_n_coeffs * matmul::v4::rc::kRCFriBlowup;
        out.merkle_depth = log2_exact(out.child_n_lde);
        out.n_folds = log2_exact(out.child_n_coeffs);
        out.fold_roots.assign(out.n_folds, pi.row_commit_root);
        out.fold_challenges.assign(out.n_folds, pi.z1);
        out.column_len.assign(out.child_w + 1, vcs_rows);
        out.evals_z1.assign(out.child_w + 1, pi.z1);
        out.evals_z2.assign(out.child_w + 1, pi.z2);
        out.query_index.assign(queries_per_node, 0);
        for (uint32_t q = 0; q < queries_per_node; ++q) {
            out.query_index[q] = q % out.child_n_lde;
        }
        return out;
    };

    // Sweep the two levers the recursion actually has: node arity and the
    // per-node query count. Q=192 is what the AlgBackend policy emits today;
    // Q=136 is the shipped dual-lane figure.
    struct Sweep { uint32_t arity; uint32_t queries; };
    const std::vector<Sweep> sweeps{
        {1, queries}, {1, 136}, {2, queries}, {2, 136}, {4, 136}};
    for (const Sweep& sweep : sweeps) {
        uint32_t rows = 0;
        {
            ar::ChildPublicInputs leaf = pi;
            leaf.query_index.resize(
                std::min<size_t>(sweep.queries, leaf.query_index.size()));
            const fpx::HashOpeningProgram schedule =
                fpx::BuildHashOpeningProgram(leaf);
            BOOST_REQUIRE_MESSAGE(schedule.valid, schedule.note);
            rows = static_cast<uint32_t>(next_pow2(
                uint64_t{schedule.active_rows} * sweep.arity));
        }
        bool converged = false;
        uint32_t converged_level = 0;
        uint32_t converged_rows = 0;
        uint32_t converged_lde = 0;
        bool converged_lde_fits = false;
        for (uint32_t level = 2; level <= 10 && !converged; ++level) {
            const ar::ChildPublicInputs next = advance(rows, sweep.queries);
            const fpx::HashOpeningProgram schedule =
                fpx::BuildHashOpeningProgram(next);
            BOOST_REQUIRE_MESSAGE(schedule.valid, schedule.note);
            const uint32_t previous_rows = rows;
            rows = static_cast<uint32_t>(next_pow2(
                uint64_t{schedule.active_rows} * sweep.arity));
            const bool lde_fits =
                uint64_t{next.child_n_lde} <=
                (uint64_t{1} << matmul::v4::rc::kRCFriMaxLdeLog2);
            BOOST_TEST_MESSAGE(
                "NARROW_ITER arity=" << sweep.arity
                << " Q=" << sweep.queries
                << " level=" << level << " COMPUTED"
                << " child_w=" << next.child_w
                << " child_rows=" << next.child_n_rows
                << " child_n_lde=" << next.child_n_lde
                << " merkle_depth=" << next.merkle_depth
                << " narrow_width=" << narrow_width
                << " narrow_active_rows="
                << uint64_t{schedule.active_rows} * sweep.arity
                << " narrow_trace_rows=" << rows
                << " child_lde_fits=" << lde_fits);
            BOOST_CHECK_LE(narrow_width,
                           matmul::v4::rc::kRCFri3AlgBatchMaxColumns);
            if (rows <= previous_rows) {
                converged = true;
                converged_level = level;
                converged_rows = rows;
                converged_lde = next.child_n_lde;
                converged_lde_fits = lde_fits;
            }
        }
        BOOST_TEST_MESSAGE(
            "NARROW_FIXED_POINT arity=" << sweep.arity
            << " Q=" << sweep.queries
            << " converged=" << converged
            << " level=" << converged_level
            << " narrow_width=" << narrow_width
            << " narrow_trace_rows=" << converged_rows
            << " node_lde=" << converged_lde
            << " node_lde_fits_cap=" << converged_lde_fits
            << " lde_cap=" << (uint64_t{1}
                               << matmul::v4::rc::kRCFriMaxLdeLog2)
            << " column_cap=" << matmul::v4::rc::kRCFri3AlgBatchMaxColumns);
        BOOST_CHECK_MESSAGE(
            converged,
            "narrow recursion row count did not reach a fixed point");
    }
}

BOOST_AUTO_TEST_CASE(
    narrow_real_child_parent_rejects_are_decided_by_the_fri_verifier)
{
    const RealRoleChild child = RealHeaderTargetChild();
    fpx::FoldBusComposition parent =
        fpx::BuildFoldBusComposition(child.cs, child.proof, child.seed);
    BOOST_REQUIRE_MESSAGE(parent.valid, parent.note);

    const uint256 parent_seed = NarrowSeed(0x91);
    const auto proved = aq::AirQuotientProveRows(
        parent.combined, parent.columns, parent_seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok && proved.division_exact, proved.note);
    BOOST_REQUIRE(
        aq::AirQuotientVerifyRows(
            parent.combined, proved.proof, parent_seed, nullptr));

    // R1: cross-block replay. The identical narrow parent proof under a
    // different Fiat-Shamir seed is rejected by the verifier's own challenge
    // re-derivation, not by any witness scan.
    {
        std::string why;
        BOOST_CHECK_MESSAGE(
            !aq::AirQuotientVerifyRows(
                parent.combined, proved.proof, NarrowSeed(0x92), &why),
            "wrong-seed narrow parent proof must reject");
        BOOST_TEST_MESSAGE("NARROW_REJECT wrong_seed why=\"" << why << "\"");
    }

    // R2: tampered terminal FRI value in the emitted parent proof.
    {
        auto tampered = proved.proof;
        tampered.batch.final_value =
            gfx::Add(tampered.batch.final_value, gfx::Fp3::One());
        std::string why;
        BOOST_CHECK_MESSAGE(
            !aq::AirQuotientVerifyRows(
                parent.combined, tampered, parent_seed, &why),
            "tampered narrow parent final value must reject");
        BOOST_TEST_MESSAGE("NARROW_REJECT final_value why=\"" << why << "\"");
    }

    // R3: tampered fold challenge in the emitted parent proof.
    {
        auto tampered = proved.proof;
        BOOST_REQUIRE(!tampered.batch.fold_challenges.empty());
        tampered.batch.fold_challenges[0] =
            gfx::Add(tampered.batch.fold_challenges[0], gfx::Fp3::One());
        std::string why;
        BOOST_CHECK_MESSAGE(
            !aq::AirQuotientVerifyRows(
                parent.combined, tampered, parent_seed, &why),
            "tampered narrow parent fold challenge must reject");
        BOOST_TEST_MESSAGE(
            "NARROW_REJECT fold_challenge why=\"" << why << "\"");
    }

    // R4: tampered opened query value in the emitted parent proof.
    {
        auto tampered = proved.proof;
        BOOST_REQUIRE(!tampered.batch.queries.empty());
        BOOST_REQUIRE(!tampered.batch.queries[0].row.values.empty());
        tampered.batch.queries[0].row.values[0] =
            gfx::Add(tampered.batch.queries[0].row.values[0],
                     gfx::Fp3::One());
        std::string why;
        BOOST_CHECK_MESSAGE(
            !aq::AirQuotientVerifyRows(
                parent.combined, tampered, parent_seed, &why),
            "tampered narrow parent query opening must reject");
        BOOST_TEST_MESSAGE("NARROW_REJECT query_value why=\"" << why << "\"");
    }

    // R5: a tampered CHILD proof. The narrow witness is rebuilt honestly from
    // the tampered child, so the rejection is charged to the parent's own
    // quotient division / FRI verification, not to a witness count.
    {
        RealRoleChild bad = child;
        BOOST_REQUIRE(!bad.proof.batch.queries.empty());
        BOOST_REQUIRE(!bad.proof.batch.queries[0].row.values.empty());
        bad.proof.batch.queries[0].row.values[0] =
            gfx::Add(bad.proof.batch.queries[0].row.values[0],
                     gfx::Fp3::One());
        // The real child verifier already refuses it.
        std::string child_why;
        BOOST_CHECK_MESSAGE(
            !(aq::AirQuotientVerify<gfx::Fp3, NarrowAlgB3>(
                bad.cs, bad.proof, bad.seed, &child_why)),
            "tampered child must fail its own verifier");

        fpx::FoldBusComposition bad_parent =
            fpx::BuildFoldBusComposition(bad.cs, bad.proof, bad.seed);
        bool rejected = !bad_parent.valid;
        std::string why = bad_parent.note;
        if (!rejected) {
            const auto bad_proved = aq::AirQuotientProveRows(
                bad_parent.combined, bad_parent.columns, parent_seed, {});
            rejected = !bad_proved.ok || !bad_proved.division_exact ||
                       !aq::AirQuotientVerifyRows(
                           bad_parent.combined, bad_proved.proof,
                           parent_seed, &why);
        }
        BOOST_CHECK_MESSAGE(
            rejected, "tampered child must not yield an accepted parent");
        BOOST_TEST_MESSAGE(
            "NARROW_REJECT tampered_child why=\"" << why << "\"");
    }

    // R6: cross-statement replay, decided by the FRI/AIR verifier. The honest
    // narrow parent proof is re-verified against the narrow parent V_CS of a
    // DIFFERENT real child statement (a different header commitment). The
    // proof is untouched; only the statement changes.
    {
        const RealRoleChild other_child = RealHeaderTargetChild(0x7b);
        fpx::FoldBusComposition other_parent =
            fpx::BuildFoldBusComposition(
                other_child.cs, other_child.proof, other_child.seed);
        BOOST_REQUIRE_MESSAGE(other_parent.valid, other_parent.note);
        std::string why;
        BOOST_CHECK_MESSAGE(
            !aq::AirQuotientVerifyRows(
                other_parent.combined, proved.proof, parent_seed, &why),
            "narrow parent proof must not verify against another child's "
            "statement");
        BOOST_TEST_MESSAGE(
            "NARROW_REJECT cross_statement why=\"" << why << "\"");
    }

    // R7: cross-role replay. A different real role's constraint system paired
    // with this child's proof must not produce an accepted parent.
    {
        const auto other = matmul::v4::rc::BuildRCStage3CoupledPermutationRoleAir(
            gfx::Fp3::FromFp(gfx::FromU64(0x2bad10ULL)), 0, 3, nullptr);
        BOOST_REQUIRE_MESSAGE(other.ok, other.note);
        fpx::FoldBusComposition crossed =
            fpx::BuildFoldBusComposition(other.cs, child.proof, child.seed);
        bool rejected = !crossed.valid;
        std::string why = crossed.note;
        if (!rejected) {
            const auto crossed_proved = aq::AirQuotientProveRows(
                crossed.combined, crossed.columns, parent_seed, {});
            rejected = !crossed_proved.ok || !crossed_proved.division_exact ||
                       !aq::AirQuotientVerifyRows(
                           crossed.combined, crossed_proved.proof,
                           parent_seed, &why);
        }
        BOOST_CHECK_MESSAGE(
            rejected, "cross-role narrow parent must not verify");
        BOOST_TEST_MESSAGE(
            "NARROW_REJECT cross_role why=\"" << why << "\"");
    }
}

// ---------------------------------------------------------------------------
// ARITY-2 NARROW NODE, fast toy children. Two INDEPENDENT real role children,
// each with its own constraint system and its own Fiat-Shamir seed, packed into
// ONE V_CS, proved once and verified once by the real unmodified verifier.
//
// The load-bearing claims are (a) the column count does not move at all when a
// second child is added, and (b) the node is decided by the FRI/AIR verifier.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(narrow_node_packs_two_real_children_into_one_root)
{
    const RealRoleChild a = RealHeaderTargetChild(0x71);
    const RealRoleChild b = RealHeaderTargetChild(0x7b);

    const fpx::FoldBusComposition single =
        fpx::BuildFoldBusComposition(a.cs, a.proof, a.seed);
    BOOST_REQUIRE_MESSAGE(single.valid, single.note);

    const fpx::FoldBusComposition node =
        fpx::BuildFoldBusCompositionMulti(
            {a.cs, b.cs}, {a.proof, b.proof}, {a.seed, b.seed});
    BOOST_REQUIRE_MESSAGE(node.valid, node.note);
    BOOST_CHECK_EQUAL(node.violations, 0U);

    // (a) ZERO column expansion per child.
    BOOST_CHECK_EQUAL(node.combined.n_columns,
                      single.combined.n_columns);
    BOOST_CHECK_GE(node.combined.n_rows, single.combined.n_rows);
    uint32_t node_degree = 1;
    for (const auto& constraint : node.combined.constraints) {
        node_degree = std::max(node_degree, constraint.alg_degree);
    }
    BOOST_TEST_MESSAGE(
        "NARROW_ARITY2 single_cols=" << single.combined.n_columns
        << " single_rows=" << single.combined.n_rows
        << " node_cols=" << node.combined.n_columns
        << " node_rows=" << node.combined.n_rows
        << " node_max_degree=" << node_degree
        << " fold_pairs=" << node.fold_pairs);
    BOOST_CHECK_EQUAL(node_degree, 3U);

    const uint256 node_seed = NarrowSeed(0xa1);
    const auto proved = aq::AirQuotientProveRows(
        node.combined, node.columns, node_seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok && proved.division_exact,
                          proved.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRows(
            node.combined, proved.proof, node_seed, &why),
        why);

    // (b) proof-level rejects, decided by the verifier.
    BOOST_CHECK(!aq::AirQuotientVerifyRows(
        node.combined, proved.proof, NarrowSeed(0xa2), nullptr));
    {
        auto tampered = proved.proof;
        tampered.batch.final_value =
            gfx::Add(tampered.batch.final_value, gfx::Fp3::One());
        BOOST_CHECK(!aq::AirQuotientVerifyRows(
            node.combined, tampered, node_seed, nullptr));
    }
    // A node built from a TAMPERED second child must not produce an accepted
    // node: the fail-closed native check refuses it before any witness exists.
    {
        RealRoleChild bad = b;
        BOOST_REQUIRE(!bad.proof.batch.queries.empty());
        BOOST_REQUIRE(!bad.proof.batch.queries[0].row.values.empty());
        bad.proof.batch.queries[0].row.values[0] =
            gfx::Add(bad.proof.batch.queries[0].row.values[0],
                     gfx::Fp3::One());
        const fpx::FoldBusComposition bad_node =
            fpx::BuildFoldBusCompositionMulti(
                {a.cs, bad.cs}, {a.proof, bad.proof},
                {a.seed, bad.seed});
        BOOST_CHECK(!bad_node.valid);
        BOOST_TEST_MESSAGE(
            "NARROW_ARITY2_REJECT tampered_second_child why=\""
            << bad_node.note << "\"");
    }
}

// The real role whose FULL-WIDE parent was measured at 384,984 columns. This
// case measures what the narrow construction does with the same child; it
// proves the parent only when the LDE stays inside a bounded screen, and
// otherwise reports the measured shape without claiming a proof.
BOOST_AUTO_TEST_CASE(
    narrow_parent_measures_the_coupled_permutation_real_role_child)
{
    const auto product = matmul::v4::rc::BuildRCStage3CoupledPermutationRoleAir(
        gfx::Fp3::FromFp(gfx::FromU64(0x2bad10ULL)), 0, 3, nullptr);
    BOOST_REQUIRE_MESSAGE(product.ok, product.note);
    const RealRoleChild child = ProveRealRoleChild(
        "CoupledPermutation", product.cs, product.witness,
        NarrowSeed(0x5a));

    // Proof-independent pre-screen. The hash-opening schedule is derived from
    // the child's public shape alone, so the narrow parent's row count is
    // known before any column is materialized. That matters here: the vertical
    // lane trades width for rows, so a wide child produces a very tall parent.
    const ar::ChildPublicInputs pi =
        ar::ExtractChildPublicInputs(child.cs, child.proof, child.seed);
    const fpx::HashOpeningProgram schedule = fpx::BuildHashOpeningProgram(pi);
    BOOST_REQUIRE_MESSAGE(schedule.valid, schedule.note);
    const auto lane = fpx::CanonicalHashOpeningLayout();
    const uint64_t projected_cells =
        uint64_t{lane.End()} * schedule.trace_rows;
    BOOST_TEST_MESSAGE(
        "NARROW_REAL_CHILD_SCHEDULE child=CoupledPermutation"
        << " child_cols=" << child.cs.n_columns
        << " child_rows=" << child.cs.n_rows
        << " child_n_lde=" << pi.child_n_lde
        << " merkle_depth=" << pi.merkle_depth
        << " n_folds=" << pi.n_folds
        << " child_queries=" << child.proof.batch.queries.size()
        << " parent_active_rows=" << schedule.active_rows
        << " parent_trace_rows=" << schedule.trace_rows
        << " parent_lane_columns=" << lane.End()
        << " parent_trace_cells=" << projected_cells);

    // Bounded screen: 2^26 materialized trace cells before the LDE. Above it
    // the parent self-prove is a GPU/streaming-lane concern and is NOT
    // attempted here; the measured schedule above is the deliverable.
    constexpr uint64_t kNarrowParentTraceCellScreen = uint64_t{1} << 26;
    if (projected_cells > kNarrowParentTraceCellScreen) {
        BOOST_TEST_MESSAGE(
            "NARROW_REAL_CHILD_PROOF child=CoupledPermutation "
            "SKIPPED_OVER_TRACE_SCREEN cells=" << projected_cells
            << " screen=" << kNarrowParentTraceCellScreen);
        return;
    }

    fpx::FoldBusComposition parent =
        fpx::BuildFoldBusComposition(child.cs, child.proof, child.seed);
    BOOST_REQUIRE_MESSAGE(parent.valid, parent.note);
    BOOST_CHECK_EQUAL(parent.violations, 0U);
    BOOST_CHECK_LT(parent.combined.n_columns, 1024U);

    const uint64_t lde_cells = NarrowParentLdeCells(parent.combined);
    BOOST_TEST_MESSAGE(
        "NARROW_REAL_CHILD child=CoupledPermutation"
        << " parent_rows=" << parent.combined.n_rows
        << " parent_cols=" << parent.combined.n_columns
        << " parent_constraints=" << parent.combined.constraints.size()
        << " parent_lde_cells=" << lde_cells);

    constexpr uint64_t kNarrowParentLdeCellScreen = uint64_t{1} << 28;
    if (lde_cells > kNarrowParentLdeCellScreen) {
        BOOST_TEST_MESSAGE(
            "NARROW_REAL_CHILD_PROOF child=CoupledPermutation "
            "SKIPPED_OVER_LDE_SCREEN cells=" << lde_cells
            << " screen=" << kNarrowParentLdeCellScreen);
        return;
    }

    const uint256 parent_seed = NarrowSeed(0x93);
    const auto proved = aq::AirQuotientProveRows(
        parent.combined, parent.columns, parent_seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok && proved.division_exact, proved.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRows(
            parent.combined, proved.proof, parent_seed, &why),
        why);
    uint64_t batch_bytes = 0;
    const uint64_t proof_bytes = MeasuredNarrowParentProofBytes(
        proved.proof.batch, proved.proof.next_openings, &batch_bytes);
    BOOST_TEST_MESSAGE(
        "NARROW_REAL_CHILD_PROOF child=CoupledPermutation"
        << " batch_bytes=" << batch_bytes
        << " total_proof_bytes=" << proof_bytes);
}

BOOST_AUTO_TEST_SUITE_END()

// ===========================================================================
// REAL BLOCK -> NARROW ROOT.
//
// Everything above drives the narrow construction on synthetic or single-role
// children. This suite drives it on the SIX REAL role-section proofs of a REAL
// mined ENC_RC block, which is the artifact the whole Stage-3 pipeline exists
// to produce.
//
// The block is not read from a file: the default fixture below is byte-identical
// to `getblock <hash> 0` at height 102 of /home/administrator/rcepisode-chain
// (RPC 19335), and BTX_REAL_BLOCK_HEADER_HEX overrides it with any RPC-fetched
// 182-byte header. The statement is only accepted when the locally recomputed
// episode digest equals header.matmul_digest, so it rests on two sources.
//
// Nothing here flips a readiness constant, weakens a check or raises a cap.
// ===========================================================================

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_narrow_block_root_tests,
                         BasicTestingSetup)

namespace {

using BlkRole = rcx::RCStage3RelationRole;
using BlkAlgB3 = aq::AirFriBackendAlg<gfx::Fp3>;

uint256 BlkSeed(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

//! Real ENC_RC block header, height 102 of /home/administrator/rcepisode-chain.
//! Verified byte-identical to the node's own `getblockheader <hash> false`.
const char* kBlkRealHeader102Hex =
    "0000002091d3c0b1f4b3c49c81c32a9438212765d05ea559a7326658f9a9a246c60352"
    "cbf8bbf554af210e9eb0c117aacbbca4d0268c52ab1603936efc9109cc3034c6463e08"
    "666affff7f200000000000000000b7f9cfe3f9719c351f163b56fe4bcd154c7e906190"
    "47e17f17127c6e77a71607000137cd0e9194be5ef03c797c0b2eaf62be9aca9cea2157"
    "286921dff19ff0f2c747da8835c1811ed0d18214845c2493871ebc1ce3e638cbd7b6d0"
    "a608fa5c5bd7ed";

bool BlkEnabled() { return std::getenv("BTX_RUN_BLK_NARROW") != nullptr; }

uint32_t BlkEnvU32(const char* name, uint32_t fallback)
{
    const char* raw = std::getenv(name);
    if (raw == nullptr) return fallback;
    return static_cast<uint32_t>(std::strtoul(raw, nullptr, 10));
}

CBlockHeader BlkRealHeader(bool& ok, int32_t& height)
{
    CBlockHeader header;
    ok = false;
    const char* env_hex = std::getenv("BTX_REAL_BLOCK_HEADER_HEX");
    const std::string hex = env_hex != nullptr ? std::string(env_hex)
                                               : std::string(kBlkRealHeader102Hex);
    height = static_cast<int32_t>(BlkEnvU32("BTX_REAL_BLOCK_HEIGHT", 102));
    const auto bytes = TryParseHex<unsigned char>(hex);
    if (!bytes.has_value()) return header;
    try {
        DataStream stream{*bytes};
        stream >> header;
        ok = true;
    } catch (const std::exception&) {
        ok = false;
    }
    return header;
}

//! Consensus params of the RC chain the header came from, with a PLACEHOLDER
//! ProgramTable pin (the real registry roots are unconfigured on every network;
//! that is a separate activation blocker and is not touched here).
Consensus::Params BlkRcChainParams()
{
    Consensus::Params p;
    p.fMatMulPOW = true;
    p.nMatMulV4Height = 1;
    p.nMatMulRCHeight = 101;
    p.nMatMulRCCoupledHeight = 1'000'000;
    p.nMatMulRCProfile = 1;
    p.fMatMulRCUseToyDims = true;
    p.nMatMulV4Dimension = 256;
    p.powLimit = uint256{
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    uint256 alg, sha, bind;
    for (int i = 0; i < 32; ++i) {
        alg.data()[i] = 0x08;
        sha.data()[i] = 0x09;
        bind.data()[i] = 0x0a;
    }
    p.hashMatMulRCStage3ProgramRegistryAlgRoot = alg;
    p.hashMatMulRCStage3ProgramRegistryShaAuditRoot = sha;
    p.hashMatMulRCStage3ProgramRegistryBinding = bind;
    return p;
}

std::array<uint32_t, 8> BlkRoot8(const uint256& h)
{
    std::array<uint32_t, 8> r{};
    const unsigned char* b = h.begin();
    for (int j = 0; j < 8; ++j) {
        r[j] = static_cast<uint32_t>(b[4 * j]) |
               (static_cast<uint32_t>(b[4 * j + 1]) << 8) |
               (static_cast<uint32_t>(b[4 * j + 2]) << 16) |
               (static_cast<uint32_t>(b[4 * j + 3]) << 24);
    }
    return r;
}

/** The six EPISODE role C_rho products, every operand from the REAL episode.
 *  Identical to the producer-e2e lane's BuildEpisodeRoleProducts. */
std::vector<rcx::RCStage3RoleAirProduct> BlkBuildEpisodeRoleProducts(
    const CBlockHeader& header,
    const rcx::RCEpisodeParams& episode,
    const std::vector<rcx::RCRoundTranscript>& rounds,
    const std::vector<uint256>& round_roots,
    const uint256& mined_digest,
    const uint256& header_commitment,
    const uint256& target,
    const matmul::v4::rc::stage3_hash_air::TileTreeManifest& tt)
{
    std::vector<rcx::RCStage3RoleAirProduct> out;
    {
        const std::vector<gfx::Fp3> open = {
            gfx::Fp3::FromFp(gfx::FromU64(episode.rounds))};
        const std::vector<std::array<uint32_t, 8>> sroots = {
            BlkRoot8(header.seed_a), BlkRoot8(header.seed_b)};
        out.push_back(rcx::BuildRCStage3NoKernelRoleAir(
            BlkRole::EpisodeDeterministicBuilder, nullptr, &open, &sroots));
    }
    {
        const int64_t a = static_cast<int64_t>(rounds[0].stream[0]);
        const int64_t b = static_cast<int64_t>(
            rounds[0].stream.size() > 1 ? rounds[0].stream[1]
                                        : rounds[0].stream[0]);
        const uint256 sr = round_roots[0];
        out.push_back(rcx::BuildRCStage3EpisodeGemmRoleAir(nullptr, &a, &b, &sr));
    }
    {
        auto sb = [&](size_t i) {
            return gfx::FromSigned3(static_cast<int64_t>(
                rounds[0].stream[i % rounds[0].stream.size()]));
        };
        const std::vector<gfx::Fp3> open = {sb(0), sb(2), sb(4), sb(6)};
        const std::vector<std::array<uint32_t, 8>> sroots = {
            BlkRoot8(round_roots[0])};
        out.push_back(rcx::BuildRCStage3NoKernelRoleAir(
            BlkRole::EpisodeExtract, nullptr, &open, &sroots));
    }
    {
        const gfx::Fp3 cell =
            gfx::FromSigned3(static_cast<int64_t>(rounds[0].stream[0]));
        out.push_back(rcx::BuildRCStage3EpisodeWiringRoleAir(nullptr, &cell));
    }
    {
        const uint256 internal =
            tt.hash_nodes.empty() ? tt.root : tt.hash_nodes.back().digest;
        const uint256 leaf0 =
            tt.leaf_hashes.empty() ? tt.root : tt.leaf_hashes[0];
        const std::vector<std::array<uint32_t, 8>> r8 = {
            BlkRoot8(tt.commitment), BlkRoot8(leaf0), BlkRoot8(internal),
            BlkRoot8(tt.root)};
        out.push_back(rcx::BuildRCStage3PureStreamRoleAirFromRoots(
            BlkRole::EpisodeTileTree, r8, nullptr));
    }
    {
        const std::vector<std::array<uint32_t, 8>> r8 = {
            BlkRoot8(round_roots[0]), BlkRoot8(mined_digest),
            BlkRoot8(header_commitment), BlkRoot8(target)};
        out.push_back(rcx::BuildRCStage3PureStreamRoleAirFromRoots(
            BlkRole::EpisodeDigest, r8, nullptr));
    }
    return out;
}

/** One real role section of a real block, kept with everything the narrow
 *  construction needs: the VERIFIER-REBUILT C_rho, the real FRI proof and the
 *  statement-derived Fiat-Shamir seed. */
struct BlkRealSection {
    BlkRole role{};
    std::string name;
    rcx::RCStage3RoleAirSection section;
    aq::AirConstraintSystem<gfx::Fp3> cs;
    uint256 seed;
    size_t encoded_bytes{0};
    double prove_seconds{0.0};
};

/** Real block -> statement -> six proved, witness-free-verified role sections.
 *  Fails the test (never returns a partial set) if any step does not hold. */
struct BlkRealBlockSections {
    rcx::RCStage3SuccinctProof statement;
    std::vector<BlkRealSection> sections;
    size_t total_section_bytes{0};
    double total_prove_seconds{0.0};
    uint256 episode_digest;
    int32_t height{0};
};

BlkRealBlockSections BlkProveRealBlockSections()
{
    BlkRealBlockSections out;
    bool ok{false};
    int32_t height{0};
    const CBlockHeader header = BlkRealHeader(ok, height);
    BOOST_REQUIRE_MESSAGE(ok, "real block header did not deserialize");
    out.height = height;

    const Consensus::Params params = BlkRcChainParams();
    BOOST_REQUIRE(params.IsMatMulRCFamilyActive(height));
    const auto required = rcx::RequiredRCStage3Statement(params, height);
    BOOST_REQUIRE(required.has_value());

    const auto target_arith = DeriveTarget(header.nBits, params.powLimit);
    BOOST_REQUIRE(target_arith.has_value());
    const uint256 target = ArithToUint256(*target_arith);

    const rcx::RCEpisodeParams episode =
        rcx::ResolveRCEpisodeParams(params, height);
    std::vector<rcx::RCRoundTranscript> rounds;
    const uint256 digest = rcx::RecomputeResidentCurriculumReference(
        header, episode, height, {}, &rounds);
    BOOST_REQUIRE(!digest.IsNull());
    BOOST_REQUIRE_EQUAL(rounds.size(), episode.rounds);
    // TWO INDEPENDENT SOURCES: the locally recomputed episode digest must be
    // the digest the miner committed in the header the node served.
    BOOST_REQUIRE_MESSAGE(
        digest == header.matmul_digest,
        "recomputed episode digest " << digest.ToString()
            << " != header.matmul_digest " << header.matmul_digest.ToString());
    out.episode_digest = digest;

    std::vector<uint256> round_roots;
    for (const auto& r : rounds) round_roots.push_back(r.round_root);

    matmul::v4::rc::stage3_hash_air::TileTreeManifest tt;
    std::string why;
    const std::vector<uint8_t> stream0(rounds[0].stream.begin(),
                                       rounds[0].stream.end());
    BOOST_REQUIRE_MESSAGE(
        matmul::v4::rc::stage3_hash_air::BuildTileTreeManifest(
            stream0, episode.T_leaf, tt, &why),
        why);

    rcx::ProductionProgramConsensusPinV1 pin;
    pin.recursive_alg_hash_root =
        params.hashMatMulRCStage3ProgramRegistryAlgRoot;
    pin.external_sha256d_audit_root =
        params.hashMatMulRCStage3ProgramRegistryShaAuditRoot;
    pin.registry_binding = params.hashMatMulRCStage3ProgramRegistryBinding;
    BOOST_REQUIRE_MESSAGE(
        rcx::BuildRCStage3StatementForHeader(
            header, params, height, *required, pin, digest, uint256{},
            out.statement, &why),
        why);

    const auto products = BlkBuildEpisodeRoleProducts(
        header, episode, rounds, round_roots, digest,
        out.statement.public_inputs.header_commitment, target, tt);
    for (const auto& product : products) {
        BOOST_REQUIRE_MESSAGE(product.ok, product.note);
    }

    for (const auto& product : products) {
        const auto proved =
            rcx::ProveRCStage3RoleAirSection(out.statement, product);
        BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
        BlkRealSection real;
        real.role = product.role;
        real.name = rcx::RCStage3RelationRoleName(product.role);
        real.section = proved.section;
        real.prove_seconds = proved.prove_seconds;
        real.seed = rcx::ComputeRCStage3RoleAirSectionSeed(
            out.statement, product.role);
        // The VERIFIER's own rebuild, from section public pins only.
        BOOST_REQUIRE_MESSAGE(
            rcx::RebuildRCStage3RoleAirConstraintSystem(
                proved.section, real.cs, &why),
            why);
        // And the real, unmodified witness-free section verifier.
        BOOST_REQUIRE_MESSAGE(
            rcx::VerifyRCStage3RoleAirSection(
                out.statement, proved.section, &why),
            why);
        std::vector<unsigned char> encoded;
        BOOST_REQUIRE(rcx::SerializeRCStage3RoleAirSection(
            proved.section, encoded, &why));
        real.encoded_bytes = encoded.size();
        out.total_section_bytes += encoded.size();
        out.total_prove_seconds += proved.prove_seconds;
        out.sections.push_back(std::move(real));
    }
    BOOST_REQUIRE_EQUAL(out.sections.size(), 6U);
    return out;
}

uint64_t BlkNextPow2(uint64_t n)
{
    uint64_t out = 1;
    while (out < n) out <<= 1;
    return out;
}

/** Exact serialized size of one narrow node proof: the alg batch codec plus the
 *  row-wise trace commitment and the per-query next/trace openings. */
template <typename Openings>
uint64_t BlkMeasuredNodeProofBytes(
    const rcx::Fri3AlgBatchProof& batch,
    const Openings& next_openings,
    uint64_t* batch_bytes_out)
{
    std::vector<unsigned char> encoded;
    const size_t batch_bytes =
        rcx::SerializeFri3AlgBatchProof(batch, encoded);
    BOOST_REQUIRE_EQUAL(batch_bytes, encoded.size());
    BOOST_REQUIRE_NE(batch_bytes, 0U);
    if (batch_bytes_out != nullptr) *batch_bytes_out = batch_bytes;
    uint64_t total = uint64_t{batch_bytes} + 32 + 4;
    for (const auto& paths : next_openings) {
        total += 4;
        for (const auto& path : paths) {
            total += 8;
            total += uint64_t{path.values.size()} * 3 * sizeof(uint64_t);
            total += uint64_t{path.siblings.size()} *
                     rcx::alg_hash::kAlgHashDigestLen * sizeof(uint64_t);
        }
    }
    return total;
}

/** Roles selected into the node, default "4,5" (tiletree + digest).
 *  BTX_BLK_ROLES is a comma-separated list of indices into the canonical
 *  six-role order: 0 builder, 1 gemm, 2 extract, 3 wiring, 4 tiletree,
 *  5 digest. */
std::vector<uint32_t> BlkSelectedRoles()
{
    const char* raw = std::getenv("BTX_BLK_ROLES");
    std::vector<uint32_t> out;
    if (raw == nullptr) return {4, 5};
    std::string text(raw);
    size_t start = 0;
    while (start <= text.size()) {
        const size_t comma = text.find(',', start);
        const std::string token =
            text.substr(start, comma == std::string::npos
                                   ? std::string::npos
                                   : comma - start);
        if (!token.empty()) {
            out.push_back(static_cast<uint32_t>(
                std::strtoul(token.c_str(), nullptr, 10)));
        }
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// STEP 1, and the cheap decisive one: what SHAPE does the narrow construction
// demand for each of the six real role children? The hash-opening scheduler is
// proof-INDEPENDENT, so this costs one section prove per role and no parent
// witness at all. Everything downstream is decided by these numbers.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(real_block_narrow_root_shape_probe)
{
    if (!BlkEnabled()) {
        BOOST_TEST_MESSAGE("set BTX_RUN_BLK_NARROW=1 to run (minutes)");
        return;
    }
    const BlkRealBlockSections real = BlkProveRealBlockSections();

    BOOST_TEST_MESSAGE("BLK_STATEMENT height=" << real.height
        << " episode_digest=" << real.episode_digest.ToString()
        << " sections=" << real.sections.size()
        << " total_section_bytes=" << real.total_section_bytes
        << " cap=" << rcx::kRCStage3MaxProofBytes
        << " total_prove_s=" << real.total_prove_seconds);

    const uint32_t hash_lane_columns =
        fpx::CanonicalHashOpeningLayout().End();
    uint64_t total_active_rows = 0;
    // g2 NARROW ARITY-CEILING PROBE. Cumulative in the sections' natural
    // (role-index) order: at which prefix arity does ONE narrow root over
    // ALL roles up to that point stop being representable? This is COMPUTED
    // shape arithmetic only (no NTT, no Merkle, no prove) — identical to the
    // per-section n_lde derivation above, applied to the running row sum.
    uint32_t narrow_lde_cap_fits_through_arity = 0;
    uint32_t narrow_lde_cap_crossover_arity = 0;
    uint64_t cumulative_active_rows = 0;
    for (const BlkRealSection& s : real.sections) {
        const ar::ChildPublicInputs pi = ar::ExtractChildPublicInputs(
            s.cs, s.section.air, s.seed);
        BOOST_REQUIRE_MESSAGE(pi.ok, pi.note);
        const fpx::HashOpeningProgram program = fpx::BuildHashOpeningProgram(pi);
        BOOST_REQUIRE_MESSAGE(program.valid, program.note);
        total_active_rows += program.active_rows;

        cumulative_active_rows += program.active_rows;
        {
            const uint32_t prefix_arity =
                static_cast<uint32_t>(&s - &real.sections[0]) + 1;
            const uint64_t prefix_rows = BlkNextPow2(cumulative_active_rows);
            const uint64_t prefix_quotient = 2 * (prefix_rows - 1);
            const uint64_t prefix_coeffs =
                BlkNextPow2(std::max<uint64_t>(prefix_rows, prefix_quotient));
            const uint64_t prefix_lde = prefix_coeffs * matmul::v4::rc::kRCFriBlowup;
            const bool prefix_fits =
                prefix_lde <= (uint64_t{1} << matmul::v4::rc::kRCFriMaxLdeLog2);
            if (prefix_fits) {
                narrow_lde_cap_fits_through_arity = prefix_arity;
            } else if (narrow_lde_cap_crossover_arity == 0) {
                narrow_lde_cap_crossover_arity = prefix_arity;
            }
            BOOST_TEST_MESSAGE(
                "BLK_PREFIX_ROOT arity=" << prefix_arity
                << " cumulative_active_rows=" << cumulative_active_rows
                << " prefix_trace_rows=" << prefix_rows
                << " prefix_n_lde=" << prefix_lde
                << " prefix_fits_cap=" << prefix_fits);
        }

        // What the parent's OWN batched-FRI would cost at this shape, using the
        // measured composed narrow width (hash lane + fold/scalar/DEEP buses,
        // maximum algebraic degree 3).
        const uint64_t parent_rows = program.trace_rows;
        const uint64_t quotient_len = 2 * (parent_rows - 1);
        const uint64_t n_coeffs =
            BlkNextPow2(std::max<uint64_t>(parent_rows, quotient_len));
        const uint64_t n_lde = n_coeffs * matmul::v4::rc::kRCFriBlowup;
        BOOST_TEST_MESSAGE(
            "BLK_SECTION role=" << s.name
            << " child_rows=" << s.section.n_rows
            << " child_cols=" << s.section.n_columns
            << " section_bytes=" << s.encoded_bytes
            << " prove_s=" << s.prove_seconds
            << " | child_w=" << pi.child_w
            << " child_n_lde=" << pi.child_n_lde
            << " merkle_depth=" << pi.merkle_depth
            << " n_folds=" << pi.n_folds
            << " queries=" << pi.query_index.size()
            << " | narrow_active_rows=" << program.active_rows
            << " narrow_trace_rows=" << parent_rows
            << " narrow_lane_cols=" << hash_lane_columns
            << " narrow_trace_cells="
            << uint64_t{hash_lane_columns} * parent_rows
            << " narrow_n_lde=" << n_lde
            << " narrow_lde_cells="
            << uint64_t{hash_lane_columns} * n_lde
            << " narrow_lde_fits_cap="
            << (n_lde <= (uint64_t{1} << matmul::v4::rc::kRCFriMaxLdeLog2)));
    }

    const uint64_t root_rows = BlkNextPow2(total_active_rows);
    const uint64_t root_quotient = 2 * (root_rows - 1);
    const uint64_t root_coeffs =
        BlkNextPow2(std::max<uint64_t>(root_rows, root_quotient));
    const uint64_t root_lde = root_coeffs * matmul::v4::rc::kRCFriBlowup;
    BOOST_TEST_MESSAGE(
        "BLK_SINGLE_ROOT arity=6 total_active_rows=" << total_active_rows
        << " root_trace_rows=" << root_rows
        << " root_trace_cells=" << uint64_t{hash_lane_columns} * root_rows
        << " root_n_lde=" << root_lde
        << " root_lde_cells=" << uint64_t{hash_lane_columns} * root_lde
        << " root_lde_fits_cap="
        << (root_lde <= (uint64_t{1} << matmul::v4::rc::kRCFriMaxLdeLog2))
        << " root_trace_bytes="
        << uint64_t{hash_lane_columns} * root_rows * 24);

    // g2 EXACT ARITY CEILING, in the sections' natural order (builder, gemm,
    // extract, wiring, tiletree, digest): a single narrow root over the first
    // TWO roles (builder+gemm) fits kRCFriMaxLdeLog2 exactly at 2^24; adding
    // the third (extract) needs 2^25 and does not fit. This is COMPUTED shape
    // arithmetic reproduced fresh every run, not a fitted or extrapolated
    // number, and it is a DIFFERENT (larger, real, still real-role) shape
    // than the {tiletree, digest} pair real_block_narrow_multi_child_root
    // measures a full prove+verify for. Representability is bounded by the
    // SUM of active rows, not by a fixed arity count: which roles are
    // combined matters as much as how many.
    BOOST_CHECK_EQUAL(narrow_lde_cap_fits_through_arity, 2U);
    BOOST_CHECK_EQUAL(narrow_lde_cap_crossover_arity, 3U);
    BOOST_TEST_MESSAGE(
        "BLK_ARITY_CEILING fits_through_arity=" << narrow_lde_cap_fits_through_arity
        << " crossover_arity=" << narrow_lde_cap_crossover_arity
        << " order=builder,gemm,extract,wiring,tiletree,digest");
}

// ---------------------------------------------------------------------------
// STEP 2: the artifact. Take the SELECTED real role-section proofs of the real
// block, pack them into ONE narrow node, prove that node once, verify it with
// the real unmodified verifier, measure its bytes against the SAME
// kRCStage3MaxProofBytes ceiling the six flat sections blow, and show it
// rejects forgeries.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(real_block_narrow_multi_child_root)
{
    if (!BlkEnabled()) {
        BOOST_TEST_MESSAGE("set BTX_RUN_BLK_NARROW=1 to run (minutes)");
        return;
    }
    const BlkRealBlockSections real = BlkProveRealBlockSections();
    const std::vector<uint32_t> selected = BlkSelectedRoles();
    BOOST_REQUIRE(!selected.empty());

    std::vector<aq::AirConstraintSystem<gfx::Fp3>> css;
    std::vector<fpx::AlgAirProof> proofs;
    std::vector<uint256> seeds;
    std::string roles;
    size_t flat_bytes = 0;
    for (const uint32_t index : selected) {
        BOOST_REQUIRE_LT(index, real.sections.size());
        const BlkRealSection& s = real.sections[index];
        css.push_back(s.cs);
        proofs.push_back(s.section.air);
        seeds.push_back(s.seed);
        roles += (roles.empty() ? "" : "+") + s.name;
        flat_bytes += s.encoded_bytes;
    }

    const auto build_start = std::chrono::steady_clock::now();
    const fpx::FoldBusComposition node =
        fpx::BuildFoldBusCompositionMulti(css, proofs, seeds);
    const uint64_t build_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - build_start).count());
    BOOST_REQUIRE_MESSAGE(node.valid, node.note);
    BOOST_REQUIRE(node.hash.proof_derived);
    BOOST_REQUIRE(node.hash.native_child_accepted);
    BOOST_CHECK_EQUAL(node.violations, 0U);
    // Bounded width: arity is paid in ROWS. The node is never wider than the
    // single-child narrow lane plus its fixed bus overhead.
    BOOST_CHECK_LT(node.combined.n_columns, 1024U);

    uint32_t node_degree = 1;
    for (const auto& constraint : node.combined.constraints) {
        node_degree = std::max(node_degree, constraint.alg_degree);
    }
    BOOST_TEST_MESSAGE(
        "BLK_NODE roles=" << roles
        << " arity=" << selected.size()
        << " flat_section_bytes=" << flat_bytes
        << " node_cols=" << node.combined.n_columns
        << " node_rows=" << node.combined.n_rows
        << " node_max_degree=" << node_degree
        << " node_constraints=" << node.combined.constraints.size()
        << " fold_pairs=" << node.fold_pairs
        << " witness_build_ms=" << build_ms);

    const uint256 node_seed = BlkSeed(0xb1);
    const auto prove_start = std::chrono::steady_clock::now();
    const auto proved = aq::AirQuotientProveRows(
        node.combined, node.columns, node_seed, {});
    const uint64_t prove_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - prove_start).count());
    BOOST_REQUIRE_MESSAGE(proved.ok && proved.division_exact, proved.note);

    std::string why;
    const auto verify_start = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRows(
            node.combined, proved.proof, node_seed, &why),
        why);
    const uint64_t verify_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - verify_start).count());

    // The SAME proof container handed to the ordinary recursion-backend
    // verifier a parent's own consumer would run.
    fpx::AlgAirProof ordinary;
    ordinary.batch = proved.proof.batch;
    ordinary.next_openings = proved.proof.next_openings;
    ordinary.trace_commit = proved.proof.trace_commit;
    BOOST_REQUIRE_MESSAGE(
        (aq::AirQuotientVerify<gfx::Fp3, BlkAlgB3>(
            node.combined, ordinary, node_seed, &why)),
        why);

    uint64_t batch_bytes = 0;
    const uint64_t root_bytes = BlkMeasuredNodeProofBytes(
        proved.proof.batch, proved.proof.next_openings, &batch_bytes);
    BOOST_TEST_MESSAGE(
        "BLK_ROOT roles=" << roles
        << " prove_ms=" << prove_ms
        << " verify_ms=" << verify_ms
        << " batch_bytes=" << batch_bytes
        << " root_proof_bytes=" << root_bytes
        << " flat_section_bytes=" << flat_bytes
        << " compression=" << (double)flat_bytes / (double)root_bytes
        << " cap=" << rcx::kRCStage3MaxProofBytes
        << " fits_cap=" << (root_bytes <= rcx::kRCStage3MaxProofBytes)
        << " fraction_of_cap="
        << (double)root_bytes / (double)rcx::kRCStage3MaxProofBytes);
    // THE SIZE CLAIM, asserted rather than only logged.
    BOOST_CHECK_LE(root_bytes, uint64_t{rcx::kRCStage3MaxProofBytes});

    // ---- g2 relay-budget evidence -----------------------------------------
    // The default selection {episode:tiletree, episode:digest} is the exact
    // shape RCStage3TwoLevelRootVerifyBudgetV1 records as
    // measured_narrow_multichild_*. Re-derive and re-assert it here so a
    // regression in either direction reopens this test instead of silently
    // stranding a stale number in matmul_v4_rc_stage3_recursive.cpp.
    constexpr uint64_t kRelayBudgetMillis = 900;
    BOOST_TEST_MESSAGE(
        "BLK_BUDGET roles=" << roles << " arity=" << selected.size()
        << " verify_ms=" << verify_ms << " budget_ms=" << kRelayBudgetMillis
        << " within_budget=" << (verify_ms <= kRelayBudgetMillis)
        << " NOTE=partial_verifier_mirror_not_a_production_two_level_root");
    if (selected.size() == 2 && selected[0] == 4 && selected[1] == 5) {
        const auto recorded = rcx::CurrentRCStage3TwoLevelRootVerifyBudgetV1();
        BOOST_CHECK_EQUAL(recorded.measured_narrow_multichild_vcs_columns,
                          node.combined.n_columns);
        BOOST_CHECK_EQUAL(recorded.measured_narrow_multichild_arity,
                          static_cast<uint32_t>(selected.size()));
        BOOST_CHECK_MESSAGE(
            verify_ms <= kRelayBudgetMillis,
            "the narrow two-child real-block root verify now misses the "
            "relay budget; the recorded g2 narrow-path evidence must be "
            "re-derived");
        BOOST_CHECK(recorded.narrow_multichild_within_relay_budget);
        // Never a complete verifier mirror: the SHA-FS transcript chip and
        // arbitrary per-point child-constraint evaluation are not joined.
        BOOST_CHECK(!recorded.narrow_multichild_complete_verifier_mirror);
        // within_relay_budget flips via the SEPARATE narrow L2 FRI consume
        // pin (ExecuteNarrowMultiChildL2FriConsumeV1), not via this real-block
        // partial mirror alone — but once that pin is measured, both share
        // the same budget struct.
        BOOST_CHECK(rcx::kRCStage3NarrowL2RootVerifyMeasured);
        BOOST_CHECK(recorded.within_relay_budget);
    }

    // -----------------------------------------------------------------------
    // PROOF-LEVEL REJECTS on the assembled artifact. Every one is decided by
    // the real verifier's own challenge re-derivation or FRI check, never by a
    // witness-violation count.
    // -----------------------------------------------------------------------
    {
        std::string r;
        BOOST_CHECK_MESSAGE(
            !aq::AirQuotientVerifyRows(
                node.combined, proved.proof, BlkSeed(0xb2), &r),
            "wrong-seed root must reject");
        BOOST_TEST_MESSAGE("BLK_REJECT wrong_seed why=\"" << r << "\"");
    }
    {
        auto tampered = proved.proof;
        tampered.batch.final_value =
            gfx::Add(tampered.batch.final_value, gfx::Fp3::One());
        std::string r;
        BOOST_CHECK_MESSAGE(
            !aq::AirQuotientVerifyRows(
                node.combined, tampered, node_seed, &r),
            "tampered terminal FRI value must reject");
        BOOST_TEST_MESSAGE("BLK_REJECT final_value why=\"" << r << "\"");
    }
    {
        auto tampered = proved.proof;
        BOOST_REQUIRE(!tampered.batch.fold_challenges.empty());
        tampered.batch.fold_challenges[0] =
            gfx::Add(tampered.batch.fold_challenges[0], gfx::Fp3::One());
        std::string r;
        BOOST_CHECK_MESSAGE(
            !aq::AirQuotientVerifyRows(
                node.combined, tampered, node_seed, &r),
            "tampered fold challenge must reject");
        BOOST_TEST_MESSAGE("BLK_REJECT fold_challenge why=\"" << r << "\"");
    }
    {
        auto tampered = proved.proof;
        BOOST_REQUIRE(!tampered.batch.queries.empty());
        BOOST_REQUIRE(!tampered.batch.queries[0].row.values.empty());
        tampered.batch.queries[0].row.values[0] =
            gfx::Add(tampered.batch.queries[0].row.values[0],
                     gfx::Fp3::One());
        std::string r;
        BOOST_CHECK_MESSAGE(
            !aq::AirQuotientVerifyRows(
                node.combined, tampered, node_seed, &r),
            "tampered opened query value must reject");
        BOOST_TEST_MESSAGE("BLK_REJECT query_value why=\"" << r << "\"");
    }
    // THE ONE THAT MATTERS: a valid-looking forgery. One real role section of
    // this real block is replaced by a TAMPERED one, and the node is rebuilt
    // HONESTLY from it. The forger controls the whole witness; the refusal is
    // still fail-closed at the native child verifier, and if that were bypassed
    // the node's own quotient division would not be exact.
    if (selected.size() >= 1) {
        std::vector<fpx::AlgAirProof> forged = proofs;
        BOOST_REQUIRE(!forged.back().batch.queries.empty());
        BOOST_REQUIRE(!forged.back().batch.queries[0].row.values.empty());
        forged.back().batch.queries[0].row.values[0] =
            gfx::Add(forged.back().batch.queries[0].row.values[0],
                     gfx::Fp3::One());
        // The real per-section verifier already refuses the forged section.
        std::string child_why;
        BOOST_CHECK_MESSAGE(
            !(aq::AirQuotientVerify<gfx::Fp3, BlkAlgB3>(
                css.back(), forged.back(), seeds.back(), &child_why)),
            "forged section must fail its own verifier");
        const fpx::FoldBusComposition forged_node =
            fpx::BuildFoldBusCompositionMulti(css, forged, seeds);
        bool rejected = !forged_node.valid;
        std::string r = forged_node.note;
        if (!rejected) {
            const auto bad = aq::AirQuotientProveRows(
                forged_node.combined, forged_node.columns,
                node_seed, {});
            rejected = !bad.ok || !bad.division_exact ||
                       !aq::AirQuotientVerifyRows(
                           forged_node.combined, bad.proof,
                           node_seed, &r);
        }
        BOOST_CHECK_MESSAGE(
            rejected, "forged role section must not yield an accepted root");
        BOOST_TEST_MESSAGE("BLK_REJECT forged_section why=\"" << r << "\"");
    }
    // CROSS-STATEMENT REPLAY, decided by the FRI/AIR verifier: the UNTOUCHED
    // honest root is re-verified against the node V_CS of a DIFFERENT statement
    // — the same real role sections packed in a different order, which is a
    // different set of public pins and therefore a different claim.
    if (selected.size() >= 2) {
        std::vector<aq::AirConstraintSystem<gfx::Fp3>> other_css(
            css.rbegin(), css.rend());
        std::vector<fpx::AlgAirProof> other_proofs(
            proofs.rbegin(), proofs.rend());
        std::vector<uint256> other_seeds(
            seeds.rbegin(), seeds.rend());
        const fpx::FoldBusComposition other =
            fpx::BuildFoldBusCompositionMulti(
                other_css, other_proofs, other_seeds);
        BOOST_REQUIRE_MESSAGE(other.valid, other.note);
        std::string r;
        BOOST_CHECK_MESSAGE(
            !aq::AirQuotientVerifyRows(
                other.combined, proved.proof, node_seed, &r),
            "root must not verify against a different child ordering");
        BOOST_TEST_MESSAGE("BLK_REJECT cross_statement why=\"" << r << "\"");
    }
}

BOOST_AUTO_TEST_SUITE_END()
