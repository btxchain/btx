// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_pow_composition.h>

namespace matmul::v4::rc::pow_composition {

AssessmentV1 AssessPowCompositionV1(const PremisesV1& p)
{
    AssessmentV1 out;
    out.regrind_budget_bits = p.regrind_budget_bits;
    out.algebraic_regrind_deduction_bits =
        p.algebraic_regrind_deduction_bits;

    if (p.version != kPowCompositionVersionV1) {
        out.note = "stage3:pow_composition:version";
        return out;
    }

    out.consensus_statement_binding_complete =
        p.header_projection_and_final_digest_disjoint &&
        p.params_height_target_and_sigma_bound &&
        p.digest_compared_to_target_as_integer &&
        p.complete_proof_payload_transcript_bound &&
        p.statement_bound_before_first_proof_commitment;

    out.complete_tensor_work_relation =
        p.builder_params_and_seed_chain_proved &&
        p.every_gemm_and_signed_range_proved &&
        p.every_extract_and_wiring_step_proved &&
        p.tile_tree_and_round_order_proved &&
        p.final_digest_and_pow_predicate_proved &&
        p.coupled_relation_additive_when_required &&
        p.all_relation_children_recursively_verified;

    out.proof_system_reduction_complete =
        p.one_canonical_transcript_dag &&
        p.full_fiat_shamir_replay_owned_by_verifier &&
        p.nirop_bcs_reduction_complete &&
        p.commitment_binding_reduction_complete &&
        p.adaptive_statement_selection_accounted;

    // The selected Q192 path is intentionally the untaxed case. If a future
    // backend enforces a squeeze predicate it needs a versioned theorem: a
    // credit and a deduction cannot silently be mixed in this V1 ledger.
    out.internal_regrind_accounting_consistent =
        p.regrind_budget_bits > 0 &&
        !p.selected_path_has_enforced_squeeze_predicate &&
        p.algebraic_regrind_deduction_bits ==
            p.regrind_budget_bits;
    out.no_double_counting_of_oracle_work =
        p.bcs_term_is_all_query_work_bound &&
        p.bcs_regrind_not_double_charged;
    out.proof_internal_and_mining_work_separated =
        out.internal_regrind_accounting_consistent &&
        out.no_double_counting_of_oracle_work &&
        p.statement_bound_before_first_proof_commitment &&
        p.adaptive_statement_selection_accounted;
    out.authority_path_is_succinct_only =
        p.sampled_carrier_excluded_from_authority &&
        p.exact_replay_excluded_from_authority;

    out.false_acceptance_event_decomposition_complete =
        out.consensus_statement_binding_complete &&
        out.complete_tensor_work_relation &&
        out.proof_system_reduction_complete &&
        out.proof_internal_and_mining_work_separated &&
        out.authority_path_is_succinct_only;

    // The two names are kept distinct in the global ledger: the first says a
    // valid succinct statement is the complete tensor workload; the second
    // additionally says the adaptive FS/NIROP probability accounting closes.
    out.external_tensor_work_composition_complete =
        out.false_acceptance_event_decomposition_complete;
    out.pow_composition_theorem_complete =
        out.false_acceptance_event_decomposition_complete;

    if (!out.consensus_statement_binding_complete) {
        out.note = "stage3:pow_composition:consensus_statement_binding_open";
    } else if (!out.complete_tensor_work_relation) {
        out.note = "stage3:pow_composition:complete_tensor_relation_open";
    } else if (!out.proof_system_reduction_complete) {
        out.note = "stage3:pow_composition:fs_nirop_binding_reduction_open";
    } else if (!out.internal_regrind_accounting_consistent) {
        out.note = "stage3:pow_composition:regrind_accounting_inconsistent";
    } else if (!out.no_double_counting_of_oracle_work) {
        out.note = "stage3:pow_composition:bcs_oracle_work_double_count";
    } else if (!out.authority_path_is_succinct_only) {
        out.note = "stage3:pow_composition:authority_path_not_succinct_only";
    } else {
        out.note =
            "stage3:pow_composition:complete;"
            "fresh_mining_statement_bound_before_commit;"
            "internal_regrind_charged_once;"
            "sampled_and_exact_replay_excluded";
    }
    return out;
}

} // namespace matmul::v4::rc::pow_composition
