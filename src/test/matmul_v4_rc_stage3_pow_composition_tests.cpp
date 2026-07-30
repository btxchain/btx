// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_pow_composition.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace pc = matmul::v4::rc::pow_composition;
namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_pow_composition_tests,
    BasicTestingSetup)

namespace {

pc::PremisesV1 CompletePremises()
{
    pc::PremisesV1 p;
    p.header_projection_and_final_digest_disjoint = true;
    p.params_height_target_and_sigma_bound = true;
    p.digest_compared_to_target_as_integer = true;
    p.complete_proof_payload_transcript_bound = true;
    p.statement_bound_before_first_proof_commitment = true;
    p.builder_params_and_seed_chain_proved = true;
    p.every_gemm_and_signed_range_proved = true;
    p.every_extract_and_wiring_step_proved = true;
    p.tile_tree_and_round_order_proved = true;
    p.final_digest_and_pow_predicate_proved = true;
    p.coupled_relation_additive_when_required = true;
    p.all_relation_children_recursively_verified = true;
    p.one_canonical_transcript_dag = true;
    p.full_fiat_shamir_replay_owned_by_verifier = true;
    p.nirop_bcs_reduction_complete = true;
    p.commitment_binding_reduction_complete = true;
    p.adaptive_statement_selection_accounted = true;
    p.regrind_budget_bits = 40;
    p.algebraic_regrind_deduction_bits = 40;
    p.selected_path_has_enforced_squeeze_predicate = false;
    p.bcs_term_is_all_query_work_bound = true;
    p.bcs_regrind_not_double_charged = true;
    p.sampled_carrier_excluded_from_authority = true;
    p.exact_replay_excluded_from_authority = true;
    return p;
}

pc::PremisesV2 CompletePremisesV2()
{
    pc::PremisesV2 p;
    p.header_projection_and_final_digest_disjoint = true;
    p.statement_bound_before_first_proof_commitment = true;
    p.complete_proof_payload_transcript_bound = true;
    p.complete_tensor_work_relation = true;
    p.all_relation_children_recursively_verified = true;
    p.common_statement_program_trace_bound = true;
    p.common_trace_root_equality_recursively_consumed = true;
    p.lane_domains_and_oracles_disjoint = true;
    p.lane_independence_conditioned_on_common_prefix = true;
    p.common_commitment_binding_reduction_complete = true;
    p.concrete_safe_nirop_reduction_complete = true;
    p.shared_tax_predicate_recursively_consumed = true;
    p.tax_nonce_absorbed_after_both_lane_commitments = true;
    p.queries_derived_only_after_tax = true;
    p.without_replacement_sampler_recursively_consumed = true;
    p.shared_tax_is_sole_query_entropy_source = true;
    p.proof_site_upper_bound_recursively_enforced = true;
    p.adaptive_statement_selection_accounted = true;
    p.site_union_and_tax_each_charged_once = true;
    p.sampled_carrier_excluded_from_authority = true;
    p.exact_replay_excluded_from_authority = true;
    return p;
}

pc::PremisesV3 CompletePremisesV3()
{
    pc::PremisesV3 p;
    p.safe_q192_backend_consensus_selected = true;
    p.header_projection_and_final_digest_disjoint = true;
    p.statement_bound_before_first_proof_commitment = true;
    p.complete_proof_payload_transcript_bound = true;
    p.complete_tensor_work_relation = true;
    p.all_relation_children_recursively_verified = true;
    p.versioned_domain_and_fixed_k2 = true;
    p.typed_safe_domain_registry_pinned = true;
    p.safe_native_air_parity_complete = true;
    p.full_typed_transcript_program_proof_owned = true;
    p.full_typed_transcript_recursively_replayed = true;
    p.query_seed_binds_complete_post_terminal_transcript = true;
    p.canonical_query_seed_is_sole_query_source = true;
    p.all_query_candidates_recursively_consumed = true;
    p.fixed_k2_selector_recursively_enforced = true;
    p.one_trace_and_commitment_statement_bound = true;
    p.fri_bcs_reduction_complete = true;
    p.concrete_safe_nirop_reduction_complete = true;
    p.poseidon2_binding_reduction_complete = true;
    p.proof_site_upper_bound_recursively_enforced = true;
    p.adaptive_statement_selection_accounted = true;
    p.unenforced_regrind_deduction_in_fri_bits = true;
    p.site_union_and_regrind_each_charged_once = true;
    p.proof_nonce_not_credited_as_tensor_work = true;
    p.sampled_carrier_excluded_from_authority = true;
    p.exact_replay_excluded_from_authority = true;
    return p;
}

} // namespace

BOOST_AUTO_TEST_CASE(complete_decomposition_separates_mining_from_internal_grind)
{
    const auto a = pc::AssessPowCompositionV1(CompletePremises());
    BOOST_CHECK(a.consensus_statement_binding_complete);
    BOOST_CHECK(a.complete_tensor_work_relation);
    BOOST_CHECK(a.proof_system_reduction_complete);
    BOOST_CHECK(a.internal_regrind_accounting_consistent);
    BOOST_CHECK(a.proof_internal_and_mining_work_separated);
    BOOST_CHECK(a.no_double_counting_of_oracle_work);
    BOOST_CHECK(a.authority_path_is_succinct_only);
    BOOST_CHECK(a.false_acceptance_event_decomposition_complete);
    BOOST_CHECK(a.external_tensor_work_composition_complete);
    BOOST_CHECK(a.pow_composition_theorem_complete);
}

BOOST_AUTO_TEST_CASE(selected_q192_backend_is_untaxed_and_charged_once)
{
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgNumQueries, 192U);
    BOOST_CHECK_EQUAL(rc::kRCFriGrindingBits, 40U);
    BOOST_CHECK(!rc::kRCFri3AlgSingleLaneEnforcesSqueezeGrind);
    BOOST_CHECK_EQUAL(
        rc::kRCFri3AlgUnenforcedRegrindBudgetBits, 40U);
    BOOST_CHECK_EQUAL(rc::Fri3AlgProximityBoundBits(), 175);
    BOOST_CHECK_EQUAL(rc::Fri3AlgSoundnessBoundBits(), 135);

    const auto a = pc::AssessPowCompositionV1(CompletePremises());
    BOOST_CHECK(a.internal_regrind_accounting_consistent);
    BOOST_CHECK(a.no_double_counting_of_oracle_work);
}

BOOST_AUTO_TEST_CASE(regrind_credit_deduction_confusion_is_rejected)
{
    auto p = CompletePremises();
    p.selected_path_has_enforced_squeeze_predicate = true;
    auto a = pc::AssessPowCompositionV1(p);
    BOOST_CHECK(!a.internal_regrind_accounting_consistent);
    BOOST_CHECK(!a.pow_composition_theorem_complete);

    p = CompletePremises();
    p.algebraic_regrind_deduction_bits = 39;
    a = pc::AssessPowCompositionV1(p);
    BOOST_CHECK(!a.internal_regrind_accounting_consistent);
    BOOST_CHECK(!a.pow_composition_theorem_complete);

    p = CompletePremises();
    p.bcs_regrind_not_double_charged = false;
    a = pc::AssessPowCompositionV1(p);
    BOOST_CHECK(!a.no_double_counting_of_oracle_work);
    BOOST_CHECK(!a.pow_composition_theorem_complete);
}

BOOST_AUTO_TEST_CASE(sampled_or_exact_replay_cannot_be_authority)
{
    auto p = CompletePremises();
    p.sampled_carrier_excluded_from_authority = false;
    auto a = pc::AssessPowCompositionV1(p);
    BOOST_CHECK(!a.authority_path_is_succinct_only);
    BOOST_CHECK(!a.pow_composition_theorem_complete);

    p = CompletePremises();
    p.exact_replay_excluded_from_authority = false;
    a = pc::AssessPowCompositionV1(p);
    BOOST_CHECK(!a.authority_path_is_succinct_only);
    BOOST_CHECK(!a.pow_composition_theorem_complete);
}

BOOST_AUTO_TEST_CASE(every_load_bearing_premise_fails_closed)
{
    const pc::PremisesV1 all = CompletePremises();
#define REJECT_IF_DROPPED(field)                                             \
    do {                                                                     \
        auto p = all;                                                        \
        p.field = false;                                                     \
        BOOST_TEST_CONTEXT(#field) {                                         \
            BOOST_CHECK(!pc::AssessPowCompositionV1(p)                       \
                             .pow_composition_theorem_complete);             \
        }                                                                    \
    } while (false)

    REJECT_IF_DROPPED(header_projection_and_final_digest_disjoint);
    REJECT_IF_DROPPED(params_height_target_and_sigma_bound);
    REJECT_IF_DROPPED(digest_compared_to_target_as_integer);
    REJECT_IF_DROPPED(complete_proof_payload_transcript_bound);
    REJECT_IF_DROPPED(statement_bound_before_first_proof_commitment);
    REJECT_IF_DROPPED(builder_params_and_seed_chain_proved);
    REJECT_IF_DROPPED(every_gemm_and_signed_range_proved);
    REJECT_IF_DROPPED(every_extract_and_wiring_step_proved);
    REJECT_IF_DROPPED(tile_tree_and_round_order_proved);
    REJECT_IF_DROPPED(final_digest_and_pow_predicate_proved);
    REJECT_IF_DROPPED(coupled_relation_additive_when_required);
    REJECT_IF_DROPPED(all_relation_children_recursively_verified);
    REJECT_IF_DROPPED(one_canonical_transcript_dag);
    REJECT_IF_DROPPED(full_fiat_shamir_replay_owned_by_verifier);
    REJECT_IF_DROPPED(nirop_bcs_reduction_complete);
    REJECT_IF_DROPPED(commitment_binding_reduction_complete);
    REJECT_IF_DROPPED(adaptive_statement_selection_accounted);
    REJECT_IF_DROPPED(bcs_term_is_all_query_work_bound);
    REJECT_IF_DROPPED(bcs_regrind_not_double_charged);
    REJECT_IF_DROPPED(sampled_carrier_excluded_from_authority);
    REJECT_IF_DROPPED(exact_replay_excluded_from_authority);
#undef REJECT_IF_DROPPED
}

BOOST_AUTO_TEST_CASE(
    dual_q96_v2_charges_shared_tax_and_site_union_once)
{
    const auto a =
        pc::AssessPowCompositionV2(CompletePremisesV2());
    BOOST_CHECK(a.canonical_parameters);
    BOOST_CHECK_EQUAL(a.lanes, 2U);
    BOOST_CHECK_EQUAL(a.queries_per_lane, 96U);
    BOOST_CHECK_EQUAL(a.tax_bits, 20U);
    BOOST_CHECK_EQUAL(
        a.proof_sites,
        pc::kPowCompositionV2ProofSites);
    BOOST_CHECK(a.numeric_bound_machine_checked);
    BOOST_CHECK_GT(a.global_conditional_bits, 64.0);
    BOOST_CHECK(a.numeric_security_target_met);
    BOOST_CHECK(a.consensus_statement_binding_complete);
    BOOST_CHECK(a.complete_tensor_work_relation);
    BOOST_CHECK(a.common_commitment_hybrid_complete);
    BOOST_CHECK(a.independent_lane_product_justified);
    BOOST_CHECK(a.shared_tax_and_sampler_complete);
    BOOST_CHECK(a.internal_regrind_accounting_consistent);
    BOOST_CHECK(a.proof_internal_and_mining_work_separated);
    BOOST_CHECK(a.global_site_accounting_complete);
    BOOST_CHECK(a.authority_path_is_succinct_only);
    BOOST_CHECK(a.pow_composition_theorem_complete);
    BOOST_CHECK_EQUAL(
        a.exact_expression,
        "eps <= 59518769809 * "
        "(2^20 * ((17/32)^96)^2 + 2^-128 + 2^-128)");
}

BOOST_AUTO_TEST_CASE(
    dual_q96_v2_independence_tax_and_topology_fail_closed)
{
    const pc::PremisesV2 all = CompletePremisesV2();
#define REJECT_V2_IF_DROPPED(field)                                        \
    do {                                                                    \
        auto p = all;                                                       \
        p.field = false;                                                    \
        BOOST_TEST_CONTEXT(#field) {                                        \
            BOOST_CHECK(!pc::AssessPowCompositionV2(p)                      \
                             .pow_composition_theorem_complete);            \
        }                                                                   \
    } while (false)

    REJECT_V2_IF_DROPPED(
        header_projection_and_final_digest_disjoint);
    REJECT_V2_IF_DROPPED(
        statement_bound_before_first_proof_commitment);
    REJECT_V2_IF_DROPPED(
        complete_proof_payload_transcript_bound);
    REJECT_V2_IF_DROPPED(complete_tensor_work_relation);
    REJECT_V2_IF_DROPPED(
        all_relation_children_recursively_verified);
    REJECT_V2_IF_DROPPED(
        common_statement_program_trace_bound);
    REJECT_V2_IF_DROPPED(
        common_trace_root_equality_recursively_consumed);
    REJECT_V2_IF_DROPPED(lane_domains_and_oracles_disjoint);
    REJECT_V2_IF_DROPPED(
        lane_independence_conditioned_on_common_prefix);
    REJECT_V2_IF_DROPPED(
        common_commitment_binding_reduction_complete);
    REJECT_V2_IF_DROPPED(
        concrete_safe_nirop_reduction_complete);
    REJECT_V2_IF_DROPPED(
        shared_tax_predicate_recursively_consumed);
    REJECT_V2_IF_DROPPED(
        tax_nonce_absorbed_after_both_lane_commitments);
    REJECT_V2_IF_DROPPED(queries_derived_only_after_tax);
    REJECT_V2_IF_DROPPED(
        without_replacement_sampler_recursively_consumed);
    REJECT_V2_IF_DROPPED(
        shared_tax_is_sole_query_entropy_source);
    REJECT_V2_IF_DROPPED(
        proof_site_upper_bound_recursively_enforced);
    REJECT_V2_IF_DROPPED(
        adaptive_statement_selection_accounted);
    REJECT_V2_IF_DROPPED(
        site_union_and_tax_each_charged_once);
    REJECT_V2_IF_DROPPED(
        sampled_carrier_excluded_from_authority);
    REJECT_V2_IF_DROPPED(
        exact_replay_excluded_from_authority);
#undef REJECT_V2_IF_DROPPED

    auto wrong = all;
    wrong.tax_bits = 40;
    BOOST_CHECK(
        !pc::AssessPowCompositionV2(wrong)
             .canonical_parameters);
    BOOST_CHECK(
        !pc::AssessPowCompositionV2(wrong)
             .pow_composition_theorem_complete);

    wrong = all;
    wrong.queries_per_lane = 95;
    BOOST_CHECK(
        !pc::AssessPowCompositionV2(wrong)
             .pow_composition_theorem_complete);

    wrong = all;
    --wrong.proof_sites;
    BOOST_CHECK(
        !pc::AssessPowCompositionV2(wrong)
             .pow_composition_theorem_complete);
}

BOOST_AUTO_TEST_CASE(
    single_q192_safe_v3_charges_regrind_and_site_union_once)
{
    const auto a =
        pc::AssessPowCompositionV3(CompletePremisesV3());
    BOOST_CHECK(a.canonical_parameters);
    BOOST_CHECK_EQUAL(a.queries, 192U);
    BOOST_CHECK_EQUAL(a.ood_candidates, 2U);
    BOOST_CHECK_EQUAL(
        a.proof_sites,
        pc::kPowCompositionV3ProofSites);
    BOOST_CHECK(a.numeric_bound_machine_checked);
    BOOST_CHECK_GT(a.global_conditional_bits, 64.0);
    BOOST_CHECK(a.numeric_security_target_met);
    BOOST_CHECK(a.consensus_statement_binding_complete);
    BOOST_CHECK(a.complete_tensor_work_relation);
    BOOST_CHECK(a.typed_safe_transcript_complete);
    BOOST_CHECK(a.sole_query_source_recursively_enforced);
    BOOST_CHECK(a.single_oracle_reductions_complete);
    BOOST_CHECK(a.global_site_accounting_complete);
    BOOST_CHECK(a.internal_regrind_accounting_consistent);
    BOOST_CHECK(a.proof_internal_and_mining_work_separated);
    BOOST_CHECK(a.authority_path_is_succinct_only);
    BOOST_CHECK(a.pow_composition_theorem_complete);
    BOOST_CHECK_EQUAL(
        a.exact_expression,
        "eps <= 59518769809 * (2^-135 + 2^-128 + 2^-128)");

    BOOST_CHECK_EQUAL(
        pc::kPowCompositionV3Queries,
        rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(
        pc::kPowCompositionV3OodCandidates,
        rc::kRCFri3AlgSafeQ192K2OodCandidatesV13);
    BOOST_CHECK_EQUAL(
        pc::kPowCompositionV3FriBits,
        static_cast<uint32_t>(rc::Fri3AlgSoundnessBoundBits()));
    BOOST_CHECK(!rc::kRCFri3AlgSafeQ192K2ActivatedV13);

    auto live = CompletePremisesV3();
    live.safe_q192_backend_consensus_selected =
        rc::kRCFri3AlgSafeQ192K2ActivatedV13;
    BOOST_CHECK(
        !pc::AssessPowCompositionV3(live)
             .pow_composition_theorem_complete);
}

BOOST_AUTO_TEST_CASE(
    single_q192_safe_v3_every_security_premise_fails_closed)
{
    const pc::PremisesV3 all = CompletePremisesV3();
#define REJECT_V3_IF_DROPPED(field)                                        \
    do {                                                                    \
        auto p = all;                                                       \
        p.field = false;                                                    \
        BOOST_TEST_CONTEXT(#field) {                                        \
            BOOST_CHECK(!pc::AssessPowCompositionV3(p)                      \
                             .pow_composition_theorem_complete);            \
        }                                                                   \
    } while (false)

    REJECT_V3_IF_DROPPED(safe_q192_backend_consensus_selected);
    REJECT_V3_IF_DROPPED(
        header_projection_and_final_digest_disjoint);
    REJECT_V3_IF_DROPPED(
        statement_bound_before_first_proof_commitment);
    REJECT_V3_IF_DROPPED(
        complete_proof_payload_transcript_bound);
    REJECT_V3_IF_DROPPED(complete_tensor_work_relation);
    REJECT_V3_IF_DROPPED(
        all_relation_children_recursively_verified);
    REJECT_V3_IF_DROPPED(versioned_domain_and_fixed_k2);
    REJECT_V3_IF_DROPPED(typed_safe_domain_registry_pinned);
    REJECT_V3_IF_DROPPED(safe_native_air_parity_complete);
    REJECT_V3_IF_DROPPED(
        full_typed_transcript_program_proof_owned);
    REJECT_V3_IF_DROPPED(
        full_typed_transcript_recursively_replayed);
    REJECT_V3_IF_DROPPED(
        query_seed_binds_complete_post_terminal_transcript);
    REJECT_V3_IF_DROPPED(
        canonical_query_seed_is_sole_query_source);
    REJECT_V3_IF_DROPPED(
        all_query_candidates_recursively_consumed);
    REJECT_V3_IF_DROPPED(
        fixed_k2_selector_recursively_enforced);
    REJECT_V3_IF_DROPPED(
        one_trace_and_commitment_statement_bound);
    REJECT_V3_IF_DROPPED(fri_bcs_reduction_complete);
    REJECT_V3_IF_DROPPED(
        concrete_safe_nirop_reduction_complete);
    REJECT_V3_IF_DROPPED(
        poseidon2_binding_reduction_complete);
    REJECT_V3_IF_DROPPED(
        proof_site_upper_bound_recursively_enforced);
    REJECT_V3_IF_DROPPED(
        adaptive_statement_selection_accounted);
    REJECT_V3_IF_DROPPED(
        unenforced_regrind_deduction_in_fri_bits);
    REJECT_V3_IF_DROPPED(
        site_union_and_regrind_each_charged_once);
    REJECT_V3_IF_DROPPED(
        proof_nonce_not_credited_as_tensor_work);
    REJECT_V3_IF_DROPPED(
        sampled_carrier_excluded_from_authority);
    REJECT_V3_IF_DROPPED(
        exact_replay_excluded_from_authority);
#undef REJECT_V3_IF_DROPPED

    auto wrong = all;
    wrong.version = pc::kPowCompositionVersionV2;
    BOOST_CHECK(
        !pc::AssessPowCompositionV3(wrong)
             .canonical_parameters);
    BOOST_CHECK(
        !pc::AssessPowCompositionV3(wrong)
             .pow_composition_theorem_complete);

    wrong = all;
    --wrong.queries;
    BOOST_CHECK(
        !pc::AssessPowCompositionV3(wrong)
             .pow_composition_theorem_complete);

    wrong = all;
    ++wrong.ood_candidates;
    BOOST_CHECK(
        !pc::AssessPowCompositionV3(wrong)
             .pow_composition_theorem_complete);

    wrong = all;
    --wrong.proof_sites;
    BOOST_CHECK(
        !pc::AssessPowCompositionV3(wrong)
             .pow_composition_theorem_complete);

    wrong = all;
    --wrong.fri_bits;
    BOOST_CHECK(
        !pc::AssessPowCompositionV3(wrong)
             .pow_composition_theorem_complete);

    wrong = all;
    --wrong.binding_bits;
    BOOST_CHECK(
        !pc::AssessPowCompositionV3(wrong)
             .pow_composition_theorem_complete);

    wrong = all;
    --wrong.safe_nirop_bits;
    BOOST_CHECK(
        !pc::AssessPowCompositionV3(wrong)
             .pow_composition_theorem_complete);

    wrong = all;
    ++wrong.security_target_bits;
    BOOST_CHECK(
        !pc::AssessPowCompositionV3(wrong)
             .pow_composition_theorem_complete);
}

BOOST_AUTO_TEST_SUITE_END()
