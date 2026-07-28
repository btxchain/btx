// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_pow_composition.h>

#include <cmath>
#include <limits>

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

AssessmentV2 AssessPowCompositionV2(const PremisesV2& p)
{
    AssessmentV2 out;
    out.lanes = p.lanes;
    out.queries_per_lane = p.queries_per_lane;
    out.tax_bits = p.tax_bits;
    out.proof_sites = p.proof_sites;
    out.security_target_bits = p.security_target_bits;
    out.exact_expression =
        "eps <= " + std::to_string(p.proof_sites) + " * "
        "(2^20 * ((17/32)^96)^2 + 2^-128 + 2^-128)";

    out.canonical_parameters =
        p.version == kPowCompositionVersionV2 &&
        p.lanes == kPowCompositionV2Lanes &&
        p.queries_per_lane ==
            kPowCompositionV2QueriesPerLane &&
        p.tax_bits == kPowCompositionV2TaxBits &&
        p.proof_sites == kPowCompositionV2ProofSites &&
        p.common_binding_bits ==
            kPowCompositionV2BindingBits &&
        p.safe_nirop_bits == kPowCompositionV2SafeNiropBits &&
        p.security_target_bits ==
            kPowCompositionV2SecurityTargetBits;
    if (!out.canonical_parameters) {
        out.note = "stage3:pow_composition_v2:parameters";
        return out;
    }

    out.lane_proximity_probability = std::pow(
        17.0L / 32.0L,
        static_cast<long double>(p.queries_per_lane));
    out.independent_pair_probability =
        out.lane_proximity_probability *
        out.lane_proximity_probability;
    out.tax_amplified_pair_probability = std::ldexp(
        out.independent_pair_probability,
        static_cast<int>(p.tax_bits));
    out.common_binding_probability = std::ldexp(
        1.0L, -static_cast<int>(p.common_binding_bits));
    out.safe_nirop_probability = std::ldexp(
        1.0L, -static_cast<int>(p.safe_nirop_bits));
    out.per_site_failure_probability =
        out.tax_amplified_pair_probability +
        out.common_binding_probability +
        out.safe_nirop_probability;
    out.global_failure_probability =
        static_cast<long double>(p.proof_sites) *
        out.per_site_failure_probability;
    if (out.global_failure_probability > 0.0L &&
        std::isfinite(out.global_failure_probability)) {
        out.global_conditional_bits = static_cast<double>(
            -std::log2(out.global_failure_probability));
    }

    const long double reconstructed =
        static_cast<long double>(p.proof_sites) *
        (std::ldexp(
             std::pow(
                 17.0L / 32.0L,
                 static_cast<long double>(
                     p.lanes * p.queries_per_lane)),
             static_cast<int>(p.tax_bits)) +
         std::ldexp(
             1.0L,
             -static_cast<int>(p.common_binding_bits)) +
         std::ldexp(
             1.0L,
             -static_cast<int>(p.safe_nirop_bits)));
    const long double scale = std::fmax(
        std::fabs(reconstructed),
        std::numeric_limits<long double>::min());
    out.numeric_bound_machine_checked =
        std::isfinite(reconstructed) &&
        std::fabs(
            reconstructed -
            out.global_failure_probability) <=
            scale * 1.0e-15L;
    out.numeric_security_target_met =
        out.numeric_bound_machine_checked &&
        out.global_conditional_bits >=
            static_cast<double>(p.security_target_bits);

    out.consensus_statement_binding_complete =
        p.header_projection_and_final_digest_disjoint &&
        p.statement_bound_before_first_proof_commitment &&
        p.complete_proof_payload_transcript_bound;
    out.complete_tensor_work_relation =
        p.complete_tensor_work_relation &&
        p.all_relation_children_recursively_verified;
    out.common_commitment_hybrid_complete =
        p.common_statement_program_trace_bound &&
        p.common_trace_root_equality_recursively_consumed &&
        p.common_commitment_binding_reduction_complete;
    out.independent_lane_product_justified =
        p.lane_domains_and_oracles_disjoint &&
        p.lane_independence_conditioned_on_common_prefix &&
        p.concrete_safe_nirop_reduction_complete;
    out.shared_tax_and_sampler_complete =
        p.shared_tax_predicate_recursively_consumed &&
        p.tax_nonce_absorbed_after_both_lane_commitments &&
        p.queries_derived_only_after_tax &&
        p.without_replacement_sampler_recursively_consumed &&
        p.shared_tax_is_sole_query_entropy_source;
    out.internal_regrind_accounting_consistent =
        out.shared_tax_and_sampler_complete &&
        p.site_union_and_tax_each_charged_once;
    out.proof_internal_and_mining_work_separated =
        out.internal_regrind_accounting_consistent &&
        p.statement_bound_before_first_proof_commitment &&
        p.tax_nonce_absorbed_after_both_lane_commitments &&
        p.adaptive_statement_selection_accounted;
    out.global_site_accounting_complete =
        p.proof_site_upper_bound_recursively_enforced &&
        p.site_union_and_tax_each_charged_once;
    out.authority_path_is_succinct_only =
        p.sampled_carrier_excluded_from_authority &&
        p.exact_replay_excluded_from_authority;

    out.false_acceptance_event_decomposition_complete =
        out.consensus_statement_binding_complete &&
        out.complete_tensor_work_relation &&
        out.common_commitment_hybrid_complete &&
        out.independent_lane_product_justified &&
        out.shared_tax_and_sampler_complete &&
        out.proof_internal_and_mining_work_separated &&
        out.global_site_accounting_complete &&
        out.numeric_security_target_met &&
        out.authority_path_is_succinct_only;
    out.pow_composition_theorem_complete =
        out.false_acceptance_event_decomposition_complete;

    if (!out.consensus_statement_binding_complete) {
        out.note =
            "stage3:pow_composition_v2:statement_binding_open";
    } else if (!out.complete_tensor_work_relation) {
        out.note =
            "stage3:pow_composition_v2:tensor_relation_open";
    } else if (!out.common_commitment_hybrid_complete) {
        out.note =
            "stage3:pow_composition_v2:common_binding_open";
    } else if (!out.independent_lane_product_justified) {
        out.note =
            "stage3:pow_composition_v2:lane_independence_open";
    } else if (!out.shared_tax_and_sampler_complete) {
        out.note =
            "stage3:pow_composition_v2:tax_or_sampler_open";
    } else if (!out.proof_internal_and_mining_work_separated) {
        out.note =
            "stage3:pow_composition_v2:regrind_accounting_open";
    } else if (!out.global_site_accounting_complete) {
        out.note =
            "stage3:pow_composition_v2:site_bound_open";
    } else if (!out.numeric_security_target_met) {
        out.note =
            "stage3:pow_composition_v2:numeric_target_open";
    } else if (!out.authority_path_is_succinct_only) {
        out.note =
            "stage3:pow_composition_v2:authority_path_open";
    } else {
        out.note =
            "stage3:pow_composition_v2:complete;"
            "dual_q96_conditionally_independent;"
            "shared_g20_charged_once;"
            "site_union_charged_once;"
            "mining_statement_distinct_from_proof_nonce";
    }
    return out;
}

AssessmentV3 AssessPowCompositionV3(const PremisesV3& p)
{
    AssessmentV3 out;
    out.queries = p.queries;
    out.ood_candidates = p.ood_candidates;
    out.proof_sites = p.proof_sites;
    out.security_target_bits = p.security_target_bits;
    out.exact_expression =
        "eps <= " + std::to_string(p.proof_sites) +
        " * (2^-135 + 2^-128 + 2^-128)";

    out.canonical_parameters =
        p.version == kPowCompositionVersionV3 &&
        p.queries == kPowCompositionV3Queries &&
        p.ood_candidates == kPowCompositionV3OodCandidates &&
        p.proof_sites == kPowCompositionV3ProofSites &&
        p.fri_bits == kPowCompositionV3FriBits &&
        p.binding_bits == kPowCompositionV3BindingBits &&
        p.safe_nirop_bits == kPowCompositionV3SafeNiropBits &&
        p.security_target_bits ==
            kPowCompositionV3SecurityTargetBits;
    if (!out.canonical_parameters) {
        out.note = "stage3:pow_composition_v3:parameters";
        return out;
    }

    out.fri_probability = std::ldexp(
        1.0L, -static_cast<int>(p.fri_bits));
    out.binding_probability = std::ldexp(
        1.0L, -static_cast<int>(p.binding_bits));
    out.safe_nirop_probability = std::ldexp(
        1.0L, -static_cast<int>(p.safe_nirop_bits));
    out.per_site_failure_probability =
        out.fri_probability +
        out.binding_probability +
        out.safe_nirop_probability;
    out.global_failure_probability =
        static_cast<long double>(p.proof_sites) *
        out.per_site_failure_probability;
    if (out.global_failure_probability > 0.0L &&
        std::isfinite(out.global_failure_probability)) {
        out.global_conditional_bits = static_cast<double>(
            -std::log2(out.global_failure_probability));
    }

    const long double reconstructed =
        static_cast<long double>(p.proof_sites) *
        (std::ldexp(1.0L, -static_cast<int>(p.fri_bits)) +
         std::ldexp(1.0L, -static_cast<int>(p.binding_bits)) +
         std::ldexp(
             1.0L, -static_cast<int>(p.safe_nirop_bits)));
    const long double scale = std::fmax(
        std::fabs(reconstructed),
        std::numeric_limits<long double>::min());
    out.numeric_bound_machine_checked =
        std::isfinite(reconstructed) &&
        std::fabs(
            reconstructed -
            out.global_failure_probability) <=
            scale * 1.0e-15L;
    out.numeric_security_target_met =
        out.numeric_bound_machine_checked &&
        out.global_conditional_bits >=
            static_cast<double>(p.security_target_bits);

    out.consensus_statement_binding_complete =
        p.safe_q192_backend_consensus_selected &&
        p.header_projection_and_final_digest_disjoint &&
        p.statement_bound_before_first_proof_commitment &&
        p.complete_proof_payload_transcript_bound;
    out.complete_tensor_work_relation =
        p.complete_tensor_work_relation &&
        p.all_relation_children_recursively_verified;
    out.typed_safe_transcript_complete =
        p.versioned_domain_and_fixed_k2 &&
        p.typed_safe_domain_registry_pinned &&
        p.safe_native_air_parity_complete &&
        p.full_typed_transcript_program_proof_owned &&
        p.full_typed_transcript_recursively_replayed;
    out.sole_query_source_recursively_enforced =
        p.query_seed_binds_complete_post_terminal_transcript &&
        p.canonical_query_seed_is_sole_query_source &&
        p.all_query_candidates_recursively_consumed &&
        p.fixed_k2_selector_recursively_enforced;
    out.single_oracle_reductions_complete =
        p.one_trace_and_commitment_statement_bound &&
        p.fri_bcs_reduction_complete &&
        p.concrete_safe_nirop_reduction_complete &&
        p.poseidon2_binding_reduction_complete;
    out.global_site_accounting_complete =
        p.proof_site_upper_bound_recursively_enforced &&
        p.site_union_and_regrind_each_charged_once;
    out.internal_regrind_accounting_consistent =
        p.unenforced_regrind_deduction_in_fri_bits &&
        p.site_union_and_regrind_each_charged_once;
    out.proof_internal_and_mining_work_separated =
        out.internal_regrind_accounting_consistent &&
        p.statement_bound_before_first_proof_commitment &&
        p.adaptive_statement_selection_accounted &&
        p.proof_nonce_not_credited_as_tensor_work;
    out.authority_path_is_succinct_only =
        p.sampled_carrier_excluded_from_authority &&
        p.exact_replay_excluded_from_authority;

    out.false_acceptance_event_decomposition_complete =
        out.consensus_statement_binding_complete &&
        out.complete_tensor_work_relation &&
        out.typed_safe_transcript_complete &&
        out.sole_query_source_recursively_enforced &&
        out.single_oracle_reductions_complete &&
        out.global_site_accounting_complete &&
        out.proof_internal_and_mining_work_separated &&
        out.numeric_security_target_met &&
        out.authority_path_is_succinct_only;
    out.pow_composition_theorem_complete =
        out.false_acceptance_event_decomposition_complete;

    if (!out.consensus_statement_binding_complete) {
        out.note =
            "stage3:pow_composition_v3:statement_binding_open";
    } else if (!out.complete_tensor_work_relation) {
        out.note =
            "stage3:pow_composition_v3:tensor_relation_open";
    } else if (!out.typed_safe_transcript_complete) {
        out.note =
            "stage3:pow_composition_v3:typed_safe_replay_open";
    } else if (!out.sole_query_source_recursively_enforced) {
        out.note =
            "stage3:pow_composition_v3:query_source_open";
    } else if (!out.single_oracle_reductions_complete) {
        out.note =
            "stage3:pow_composition_v3:single_oracle_reduction_open";
    } else if (!out.global_site_accounting_complete) {
        out.note =
            "stage3:pow_composition_v3:site_bound_open";
    } else if (!out.proof_internal_and_mining_work_separated) {
        out.note =
            "stage3:pow_composition_v3:regrind_accounting_open";
    } else if (!out.numeric_security_target_met) {
        out.note =
            "stage3:pow_composition_v3:numeric_target_open";
    } else if (!out.authority_path_is_succinct_only) {
        out.note =
            "stage3:pow_composition_v3:authority_path_open";
    } else {
        out.note =
            "stage3:pow_composition_v3:complete;"
            "single_q192_safe_k2;"
            "one_post_terminal_query_seed;"
            "unenforced_regrind_deducted_once;"
            "site_union_charged_once;"
            "proof_nonce_not_tensor_work";
    }
    return out;
}

} // namespace matmul::v4::rc::pow_composition
