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
#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <algorithm>
#include <chrono>
#include <cmath>
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

    // The exact selected packed-four conditional manifest is smaller than
    // 2^26.  Its genuine horizontal hash-AIR packing gives both commitment
    // topologies numerical headroom; formal reductions and scheduler
    // enforcement remain independently fail-closed.
    const auto selected_manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    BOOST_REQUIRE(!selected_manifest.commitment.IsNull());
    BOOST_REQUIRE(
        selected_manifest.complete_global_upper_bound_manifest_derived);
    BOOST_REQUIRE_GT(selected_manifest.total_proof_sites, 0U);
    const nr::FriDualQ128HybridBoundAssessment exact_shared =
        nr::AssessFriDualQ128HybridBound(
            selected_manifest.total_proof_sites,
            nr::FriDualCommitmentTopology::SharedMaster);
    BOOST_REQUIRE(exact_shared.parameters_valid);
    BOOST_CHECK_CLOSE(
        exact_shared.global_site_log2, 25.9864322154, 1e-7);
    BOOST_CHECK_CLOSE(
        exact_shared.fri_all_query_bits, 102.8115402123, 1e-7);
    BOOST_CHECK_CLOSE(
        exact_shared.commitment_binding_bits, 102.0135677846, 1e-7);
    BOOST_CHECK_CLOSE(
        exact_shared.composed_union_bits, 101.3580722077, 1e-7);
    BOOST_CHECK(exact_shared.numerical_target_met);
    BOOST_CHECK(!exact_shared.exact_site_manifest_backend_enforced);
    BOOST_CHECK(!exact_shared.commitment_hybrid_reduction_complete);
    BOOST_CHECK(!exact_shared.formal_reduction_complete);
    BOOST_CHECK(!exact_shared.authority_eligible);

    const nr::FriDualQ128HybridBoundAssessment exact_duplicated =
        nr::AssessFriDualQ128HybridBound(
            selected_manifest.total_proof_sites,
            nr::FriDualCommitmentTopology::FullyDuplicatedLanes);
    BOOST_REQUIRE(exact_duplicated.parameters_valid);
    BOOST_CHECK_CLOSE(
        exact_duplicated.composed_union_bits, 100.6489074269, 1e-7);
    BOOST_CHECK(exact_duplicated.numerical_target_met);
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
    BOOST_CHECK_GT(
        two_common.independence_amplified_binding_bits, 228.0);
    BOOST_CHECK(two_common.numerical_target_met);
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
    level1 = fpx::FoldBusComposition{}; // release the level-1 witness columns

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
