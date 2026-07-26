// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_stage3_narrow_recurse.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <cmath>

namespace nr = matmul::v4::rc::narrow_recurse;
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

BOOST_AUTO_TEST_SUITE_END()
