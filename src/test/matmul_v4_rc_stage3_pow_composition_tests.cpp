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

BOOST_AUTO_TEST_SUITE_END()
