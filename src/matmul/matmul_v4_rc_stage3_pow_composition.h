// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_POW_COMPOSITION_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_POW_COMPOSITION_H

#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <cstdint>
#include <string>

namespace matmul::v4::rc::pow_composition {

inline constexpr uint16_t kPowCompositionVersionV1 = 1;

/**
 * Premises of the Stage-3 tensor-work/Fiat--Shamir composition lemma.
 *
 * This object deliberately separates three surfaces which older assessments
 * conflated:
 *
 *  1. mining chooses a public tensor-work statement;
 *  2. the complete succinct proof establishes that statement;
 *  3. the proof's internal Fiat--Shamir transcript may be re-ground.
 *
 * The sampled carrier and exact replay are not premises of this theorem.
 */
struct PremisesV1 {
    uint16_t version{kPowCompositionVersionV1};

    // Consensus/public-statement binding.
    bool header_projection_and_final_digest_disjoint{false};
    bool params_height_target_and_sigma_bound{false};
    bool digest_compared_to_target_as_integer{false};
    bool complete_proof_payload_transcript_bound{false};
    bool statement_bound_before_first_proof_commitment{false};

    // Complete tensor-work relation, including the terminal digest.
    bool builder_params_and_seed_chain_proved{false};
    bool every_gemm_and_signed_range_proved{false};
    bool every_extract_and_wiring_step_proved{false};
    bool tile_tree_and_round_order_proved{false};
    bool final_digest_and_pow_predicate_proved{false};
    bool coupled_relation_additive_when_required{false};
    bool all_relation_children_recursively_verified{false};

    // Selected proof backend and composition reductions.
    bool one_canonical_transcript_dag{false};
    bool full_fiat_shamir_replay_owned_by_verifier{false};
    bool nirop_bcs_reduction_complete{false};
    bool commitment_binding_reduction_complete{false};
    bool adaptive_statement_selection_accounted{false};

    // Regrinding accounting. The selected single-lane Q192 verifier does not
    // enforce a leading-zero squeeze predicate. `regrind_budget_bits` is an
    // explicit total-adversary-work bound and must be charged exactly once to
    // algebraic challenges. The BCS all-query term already accounts for oracle
    // work and must not be charged a second time.
    uint32_t regrind_budget_bits{0};
    uint32_t algebraic_regrind_deduction_bits{0};
    bool selected_path_has_enforced_squeeze_predicate{false};
    bool bcs_term_is_all_query_work_bound{false};
    bool bcs_regrind_not_double_charged{false};

    // Acceptance-path exclusions.
    bool sampled_carrier_excluded_from_authority{false};
    bool exact_replay_excluded_from_authority{false};
};

struct AssessmentV1 {
    uint16_t version{kPowCompositionVersionV1};
    uint32_t regrind_budget_bits{0};
    uint32_t algebraic_regrind_deduction_bits{0};

    bool consensus_statement_binding_complete{false};
    bool complete_tensor_work_relation{false};
    bool proof_system_reduction_complete{false};
    bool internal_regrind_accounting_consistent{false};
    bool proof_internal_and_mining_work_separated{false};
    bool no_double_counting_of_oracle_work{false};
    bool authority_path_is_succinct_only{false};

    /**
     * False-acceptance decomposition:
     *
     *   Accept(false tensor statement)
     *     => relation/PCS/FRI failure
     *      | commitment collision
     *      | Fiat--Shamir/NIROP failure.
     *
     * A fresh mining statement is not treated as a free extra proof attempt:
     * it is committed before the first proof commitment and is covered by the
     * adaptive-statement premise. Conversely, the internal proof nonce is not
     * mislabelled as a fresh terminal GEMM.
     */
    bool false_acceptance_event_decomposition_complete{false};
    bool external_tensor_work_composition_complete{false};
    bool pow_composition_theorem_complete{false};
    std::string note;
};

/** Pure, fail-closed implementation of the composition lemma. */
[[nodiscard]] AssessmentV1
AssessPowCompositionV1(const PremisesV1& premises);

inline constexpr uint16_t kPowCompositionVersionV2 = 2;
inline constexpr uint32_t kPowCompositionV2Lanes = 2;
inline constexpr uint32_t kPowCompositionV2QueriesPerLane = 96;
inline constexpr uint32_t kPowCompositionV2TaxBits = 20;
inline constexpr uint64_t kPowCompositionV2ProofSites =
    soundness_scenarios::kSelectedProductionProofSitesV1;
inline constexpr uint32_t kPowCompositionV2BindingBits = 128;
inline constexpr uint32_t kPowCompositionV2SafeNiropBits = 128;
inline constexpr uint32_t kPowCompositionV2SecurityTargetBits = 64;

/**
 * Versioned composition premises for the selected dual-Q96 SAFE path.
 *
 * V1 models the retired, untaxed single-lane Q192 construction. V2 instead
 * models two domain-separated Q96 lanes over one common commitment and one
 * shared field-native g=20 tax. The tax is proof-internal regrinding: it
 * amplifies the conditional algebraic error once and is never credited as
 * tensor mining work.
 */
struct PremisesV2 {
    uint16_t version{kPowCompositionVersionV2};
    uint32_t lanes{kPowCompositionV2Lanes};
    uint32_t queries_per_lane{kPowCompositionV2QueriesPerLane};
    uint32_t tax_bits{kPowCompositionV2TaxBits};
    uint64_t proof_sites{kPowCompositionV2ProofSites};
    uint32_t common_binding_bits{kPowCompositionV2BindingBits};
    uint32_t safe_nirop_bits{kPowCompositionV2SafeNiropBits};
    uint32_t security_target_bits{
        kPowCompositionV2SecurityTargetBits};

    // Consensus statement and complete tensor relation.
    bool header_projection_and_final_digest_disjoint{false};
    bool statement_bound_before_first_proof_commitment{false};
    bool complete_proof_payload_transcript_bound{false};
    bool complete_tensor_work_relation{false};
    bool all_relation_children_recursively_verified{false};

    // Common-prefix and lane reductions.
    bool common_statement_program_trace_bound{false};
    bool common_trace_root_equality_recursively_consumed{false};
    bool lane_domains_and_oracles_disjoint{false};
    bool lane_independence_conditioned_on_common_prefix{false};
    bool common_commitment_binding_reduction_complete{false};
    bool concrete_safe_nirop_reduction_complete{false};

    // One shared post-commitment tax and its query scheduler.
    bool shared_tax_predicate_recursively_consumed{false};
    bool tax_nonce_absorbed_after_both_lane_commitments{false};
    bool queries_derived_only_after_tax{false};
    bool without_replacement_sampler_recursively_consumed{false};
    bool shared_tax_is_sole_query_entropy_source{false};

    // Global topology and adaptive-selection accounting.
    bool proof_site_upper_bound_recursively_enforced{false};
    bool adaptive_statement_selection_accounted{false};
    bool site_union_and_tax_each_charged_once{false};

    // Consensus authority exclusions.
    bool sampled_carrier_excluded_from_authority{false};
    bool exact_replay_excluded_from_authority{false};
};

struct AssessmentV2 {
    uint16_t version{kPowCompositionVersionV2};
    uint32_t lanes{0};
    uint32_t queries_per_lane{0};
    uint32_t tax_bits{0};
    uint64_t proof_sites{0};
    uint32_t security_target_bits{0};

    long double lane_proximity_probability{0.0L};
    long double independent_pair_probability{0.0L};
    long double tax_amplified_pair_probability{0.0L};
    long double common_binding_probability{0.0L};
    long double safe_nirop_probability{0.0L};
    long double per_site_failure_probability{0.0L};
    long double global_failure_probability{0.0L};
    double global_conditional_bits{0.0};

    bool canonical_parameters{false};
    bool consensus_statement_binding_complete{false};
    bool complete_tensor_work_relation{false};
    bool common_commitment_hybrid_complete{false};
    bool independent_lane_product_justified{false};
    bool shared_tax_and_sampler_complete{false};
    bool internal_regrind_accounting_consistent{false};
    bool proof_internal_and_mining_work_separated{false};
    bool global_site_accounting_complete{false};
    bool numeric_bound_machine_checked{false};
    bool numeric_security_target_met{false};
    bool authority_path_is_succinct_only{false};
    bool false_acceptance_event_decomposition_complete{false};
    bool pow_composition_theorem_complete{false};
    std::string exact_expression;
    std::string note;
};

/**
 * Fail-closed dual-Q96 theorem:
 *
 *   eps <= S * (
 *       2^g * ((17/32)^Q)^2
 *       + 2^-binding
 *       + 2^-SAFE
 *   ).
 *
 * The squared proximity term is enabled only by the conditional lane-
 * independence premise. The g and S factors occur exactly once.
 */
[[nodiscard]] AssessmentV2
AssessPowCompositionV2(const PremisesV2& premises);

inline constexpr uint16_t kPowCompositionVersionV3 = 3;
inline constexpr uint32_t kPowCompositionV3Queries = 192;
inline constexpr uint32_t kPowCompositionV3OodCandidates = 2;
inline constexpr uint64_t kPowCompositionV3ProofSites =
    soundness_scenarios::kSelectedProductionProofSitesV1;
inline constexpr uint32_t kPowCompositionV3FriBits = 135;
inline constexpr uint32_t kPowCompositionV3BindingBits = 128;
inline constexpr uint32_t kPowCompositionV3SafeNiropBits = 128;
inline constexpr uint32_t kPowCompositionV3SecurityTargetBits = 64;

/**
 * Versioned composition premises for the single-lane SAFE/Q192/K=2 path.
 *
 * Unlike V2, this construction has no lane-independence or common-commitment
 * product premise.  All 192 query candidates are derived from one typed SAFE
 * query seed bound to the complete post-terminal transcript.  The 135-bit FRI
 * term already contains the conservative 40-bit deduction for the
 * non-predicated internal regrind; no proof nonce is credited as tensor work.
 */
struct PremisesV3 {
    uint16_t version{kPowCompositionVersionV3};
    uint32_t queries{kPowCompositionV3Queries};
    uint32_t ood_candidates{kPowCompositionV3OodCandidates};
    uint64_t proof_sites{kPowCompositionV3ProofSites};
    uint32_t fri_bits{kPowCompositionV3FriBits};
    uint32_t binding_bits{kPowCompositionV3BindingBits};
    uint32_t safe_nirop_bits{kPowCompositionV3SafeNiropBits};
    uint32_t security_target_bits{
        kPowCompositionV3SecurityTargetBits};

    // Consensus statement and complete tensor relation.
    bool safe_q192_backend_consensus_selected{false};
    bool header_projection_and_final_digest_disjoint{false};
    bool statement_bound_before_first_proof_commitment{false};
    bool complete_proof_payload_transcript_bound{false};
    bool complete_tensor_work_relation{false};
    bool all_relation_children_recursively_verified{false};

    // Exact typed SAFE transcript and sole query source.
    bool versioned_domain_and_fixed_k2{false};
    bool typed_safe_domain_registry_pinned{false};
    bool safe_native_air_parity_complete{false};
    bool full_typed_transcript_program_proof_owned{false};
    bool full_typed_transcript_recursively_replayed{false};
    bool query_seed_binds_complete_post_terminal_transcript{false};
    bool canonical_query_seed_is_sole_query_source{false};
    bool all_query_candidates_recursively_consumed{false};
    bool fixed_k2_selector_recursively_enforced{false};

    // Single-oracle reductions and global topology.
    bool one_trace_and_commitment_statement_bound{false};
    bool fri_bcs_reduction_complete{false};
    bool concrete_safe_nirop_reduction_complete{false};
    bool poseidon2_binding_reduction_complete{false};
    bool proof_site_upper_bound_recursively_enforced{false};
    bool adaptive_statement_selection_accounted{false};

    // Regrind and authority-path accounting.
    bool unenforced_regrind_deduction_in_fri_bits{false};
    bool site_union_and_regrind_each_charged_once{false};
    bool proof_nonce_not_credited_as_tensor_work{false};
    bool sampled_carrier_excluded_from_authority{false};
    bool exact_replay_excluded_from_authority{false};
};

struct AssessmentV3 {
    uint16_t version{kPowCompositionVersionV3};
    uint32_t queries{0};
    uint32_t ood_candidates{0};
    uint64_t proof_sites{0};
    uint32_t security_target_bits{0};

    long double fri_probability{0.0L};
    long double binding_probability{0.0L};
    long double safe_nirop_probability{0.0L};
    long double per_site_failure_probability{0.0L};
    long double global_failure_probability{0.0L};
    double global_conditional_bits{0.0};

    bool canonical_parameters{false};
    bool consensus_statement_binding_complete{false};
    bool complete_tensor_work_relation{false};
    bool typed_safe_transcript_complete{false};
    bool sole_query_source_recursively_enforced{false};
    bool single_oracle_reductions_complete{false};
    bool global_site_accounting_complete{false};
    bool internal_regrind_accounting_consistent{false};
    bool proof_internal_and_mining_work_separated{false};
    bool numeric_bound_machine_checked{false};
    bool numeric_security_target_met{false};
    bool authority_path_is_succinct_only{false};
    bool false_acceptance_event_decomposition_complete{false};
    bool pow_composition_theorem_complete{false};
    std::string exact_expression;
    std::string note;
};

/**
 * Fail-closed single-Q192 theorem:
 *
 *   eps <= S * (2^-135 + 2^-128 + 2^-128).
 *
 * The first term is the already regrind-adjusted single-lane FRI/BCS bound.
 * The other terms are the Poseidon2 commitment-binding and concrete
 * SAFE/NIROP reductions.  The site union occurs exactly once.
 */
[[nodiscard]] AssessmentV3
AssessPowCompositionV3(const PremisesV3& premises);

} // namespace matmul::v4::rc::pow_composition

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_POW_COMPOSITION_H
