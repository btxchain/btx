// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_POW_COMPOSITION_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_POW_COMPOSITION_H

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

} // namespace matmul::v4::rc::pow_composition

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_POW_COMPOSITION_H
