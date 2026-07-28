// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_nirop_hybrid.h>

#include <algorithm>
#include <limits>
#include <set>

namespace matmul::v4::rc::stage3_multirow_v11_nirop_hybrid {
namespace {

gf::Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

Fri3AlgDigest D(uint64_t base)
{
    return {
        gf::FromU64(base),
        gf::FromU64(base + 1),
        gf::FromU64(base + 2),
        gf::FromU64(base + 3)};
}

p2::StatementV1 Statement()
{
    p2::StatementV1 s;
    s.public_fs_seed =
        *uint256::FromHex(
            "0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef");
    s.pow_grind_nonce = 0;
    s.trace_rows = 512;
    s.trace_columns = 5;
    s.quotient_len = 1024;
    s.n_coeffs = 1024;
    s.blowup = kRCFriBlowup;
    s.base_column_indices = {0, 1};
    s.groups = {{
        {Fri3AlgMultiRowGroupRole::MainTrace, 0, 2, 16384, D(10)},
        {Fri3AlgMultiRowGroupRole::AuxiliaryTrace, 2, 3, 16384, D(20)},
        {Fri3AlgMultiRowGroupRole::Quotient, 5, 1, 16384, D(30)}}};
    s.column_len = {1024, 1000, 900, 800, 1024, 1024};
    for (uint32_t i = 0; i < s.column_len.size(); ++i) {
        s.evals_z1.push_back(U(100 + i));
        s.evals_z2.push_back(U(200 + i));
    }
    uint32_t leaves = 16384;
    for (uint32_t fold = 0; fold < 11; ++fold) {
        s.folds.push_back({leaves, D(1000 + 10 * fold)});
        leaves >>= 1;
    }
    s.final_value = U(9999);
    return s;
}

bool DigestDifferent(
    const Fri3AlgDigest& left, const Fri3AlgDigest& right)
{
    for (uint32_t lane = 0; lane < left.size(); ++lane) {
        if (gf::Canonical(left[lane]) != gf::Canonical(right[lane])) {
            return true;
        }
    }
    return false;
}

uint256 V13Seed(uint8_t first)
{
    uint256 seed;
    seed.begin()[0] = first;
    seed.begin()[7] = static_cast<uint8_t>(first + 1);
    seed.begin()[19] = static_cast<uint8_t>(first + 2);
    seed.begin()[31] = static_cast<uint8_t>(first + 3);
    return seed;
}

std::vector<std::vector<gf::Fp3>> V13Columns(uint64_t delta = 0)
{
    std::vector<std::vector<gf::Fp3>> columns(2);
    for (uint32_t column = 0; column < columns.size(); ++column) {
        columns[column].resize(8);
        for (uint32_t row = 0; row < columns[column].size(); ++row) {
            columns[column][row] = {
                gf::FromU64(delta + 1 + 19 * column + 7 * row),
                gf::FromU64(delta + 3 + 11 * column + 5 * row),
                gf::FromU64(delta + 9 + 13 * column + 17 * row),
            };
        }
    }
    return columns;
}

void CheckIdenticalInput(
    const CrossRoleIdenticalInputV1& witness)
{
    BOOST_CHECK(witness.lane_vectors_identical);
    BOOST_CHECK(witness.padded_inputs_identical);
    BOOST_CHECK(witness.digests_identical_without_collision);
    BOOST_REQUIRE_EQUAL(
        witness.transcript_sponge_input.size(), 7U);
    BOOST_REQUIRE_EQUAL(
        witness.row_leaf_sponge_input.size(), 7U);
    BOOST_CHECK_EQUAL(
        gf::Canonical(witness.row_cells[0].c0),
        static_cast<uint32_t>(witness.transcript_domain));
    BOOST_CHECK_EQUAL(
        gf::Canonical(witness.row_cells[0].c1),
        static_cast<uint32_t>(
            witness.transcript_domain >> 32));
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_nirop_hybrid_tests)

BOOST_AUTO_TEST_CASE(
    exact_v11_event_dag_q192_k2_and_rbr_inventory_replay)
{
    const auto audit = AssessV1(Statement());
    BOOST_CHECK_EQUAL(audit.protocol_version, 11U);
    BOOST_CHECK_EQUAL(
        audit.protocol_domain, p2::kProtocolDomainV1);
    BOOST_CHECK_EQUAL(audit.transcript_domain_count, 14U);
    BOOST_CHECK_EQUAL(audit.expected_hash_events, 424U);
    BOOST_CHECK_EQUAL(
        audit.independently_replayed_hash_events, 424U);
    BOOST_REQUIRE_EQUAL(audit.proposed_safe_io_events.size(), 424U);
    for (uint32_t event = 0;
         event < audit.proposed_safe_io_events.size(); ++event) {
        BOOST_CHECK_EQUAL(
            audit.proposed_safe_io_events[event].ordinal, event);
        BOOST_CHECK_GE(
            audit.proposed_safe_io_events[event].absorb_lanes, 2U);
        BOOST_CHECK_EQUAL(
            audit.proposed_safe_io_events[event].squeeze_lanes, 4U);
    }
    const size_t query_events = std::count_if(
        audit.proposed_safe_io_events.begin(),
        audit.proposed_safe_io_events.end(),
        [](const SafeIoEventV1& event) {
            return event.role == TranscriptRoleV1::QueryCandidate;
        });
    BOOST_CHECK_EQUAL(query_events, 384U);
    BOOST_CHECK_EQUAL(audit.queries, 192U);
    BOOST_CHECK_EQUAL(audit.query_candidates, 2U);
    BOOST_CHECK(audit.statement_shape_precedes_shape_commit);
    BOOST_CHECK(
        audit.statement_prefix_precedes_r0_rdep_roots_in_air_lambda);
    BOOST_CHECK(
        audit.statement_prefix_precedes_all_roots_in_fri_seed);
    BOOST_CHECK(audit.air_lambda_before_quotient_root);
    BOOST_CHECK(audit.all_roots_before_ood_draws);
    BOOST_CHECK(audit.ood_claims_before_batch_coefficients);
    BOOST_CHECK(audit.each_fold_root_before_its_beta);
    BOOST_CHECK(audit.terminal_before_query_seed);
    BOOST_CHECK(audit.query_seed_before_all_q192_candidates);
    BOOST_CHECK(audit.q192_k2_schedule_injective);
    BOOST_CHECK(audit.q192_with_replacement);
    BOOST_CHECK(audit.fourteen_domains_pairwise_distinct);
    BOOST_CHECK(
        audit.u64_domains_split_into_two_canonical_u32_lanes);
    BOOST_CHECK(audit.independent_replay_matches_native_receipt);
    BOOST_CHECK(audit.native_receipt_verifies);
    BOOST_CHECK(audit.rbr_parameters_match_v11);
    BOOST_CHECK(audit.q192_rbr_ledger_machine_checked);
    BOOST_CHECK_EQUAL(audit.rbr_query_proximity_bits, 135.0);
    BOOST_CHECK_EQUAL(audit.rbr_poseidon_collision_bits, 128.0);
    BOOST_CHECK_EQUAL(audit.rbr_composed_single_lane_bits, 128.0);
}

BOOST_AUTO_TEST_CASE(
    zero_work_row_leaf_vs_fs_identical_preimages_block_nirop)
{
    const auto audit = AssessV1(Statement());
    CheckIdenticalInput(audit.row_leaf_vs_coefficient);
    CheckIdenticalInput(audit.row_leaf_vs_fold_beta);
    CheckIdenticalInput(audit.row_leaf_vs_query_candidate);
    BOOST_CHECK(audit.merkle_node_capacity_domain_separated);
    BOOST_CHECK(audit.fold_leaf_fixed_width_rate_tagged);
    BOOST_CHECK(!audit.fold_leaf_capacity_domain_separated);
    BOOST_CHECK(!audit.row_leaf_role_domain_separated);
    BOOST_CHECK(!audit.merkle_oracle_and_fs_sponge_inputs_disjoint);
    BOOST_CHECK(audit.v11_uses_add_absorb_sponge);
    BOOST_CHECK(!audit.v11_uses_overwrite_mode_duplex);
    BOOST_CHECK(!audit.v11_uses_instance_derived_capacity_start);
    BOOST_CHECK(!audit.published_duplex_fs_premises_match);
    BOOST_CHECK(!audit.custom_add_absorb_hash_chain_hybrid_complete);
    BOOST_CHECK(!audit.poseidon_first_collision_hybrid_complete);
    BOOST_CHECK(!audit.nirop_bcs_composition_complete);
    BOOST_CHECK(!audit.production_authority_ready);
    BOOST_CHECK_GE(audit.required_call_site_migrations.size(), 9U);
    BOOST_CHECK(
        audit.required_protocol_change.find("version 12") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    additive_v12_capacity_roles_are_disjoint_and_host_air_exact)
{
    const auto audit = AuditTypedHashSeparationV1();
    BOOST_CHECK_EQUAL(audit.protocol_version, 12U);
    BOOST_CHECK_EQUAL(audit.role_count, 20U);
    BOOST_CHECK(audit.capacity_magic_canonical);
    BOOST_CHECK(audit.every_role_capacity_tuple_unique);
    BOOST_CHECK(audit.rate_lanes_cannot_overwrite_capacity_domain);
    BOOST_CHECK(audit.variable_length_padding_injective);
    BOOST_CHECK(audit.host_poseidon_air_permutation_parity);
    BOOST_CHECK_GE(audit.parity_calls_checked, 40U);
    BOOST_CHECK(audit.initial_call_role_encodings_disjoint);
    BOOST_CHECK(audit.fixed_leaf_node_vs_sponge_starts_disjoint);
    BOOST_CHECK(audit.row_leaf_streaming_equivalent);
    BOOST_CHECK(!audit.active_v11_backend_migrated);
    BOOST_CHECK(!audit.recursive_replay_migrated);
    BOOST_CHECK(!audit.first_collision_hybrid_ready);
    BOOST_CHECK(!audit.production_authority_ready);

    const std::vector<gf::Fp> same_lanes{
        gf::FromU64(1), gf::FromU64(2), gf::FromU64(3),
        gf::FromU64(4), gf::FromU64(5), gf::FromU64(6),
        gf::FromU64(7)};
    const auto row = TypedSpongeHashFpV1(
        TypedHashRoleV1::MerkleRowLeaf, same_lanes);
    const auto fs = TypedSpongeHashFpV1(
        TypedHashRoleV1::TranscriptBatchCoefficient, same_lanes);
    BOOST_REQUIRE(row.valid);
    BOOST_REQUIRE(fs.valid);
    BOOST_CHECK(DigestDifferent(row.digest, fs.digest));
    BOOST_REQUIRE(!row.calls.empty());
    BOOST_REQUIRE(!fs.calls.empty());
    BOOST_CHECK_EQUAL(
        gf::Canonical(
            row.calls[0].input[alg_hash::kAlgHashRate]),
        gf::Canonical(
            fs.calls[0].input[alg_hash::kAlgHashRate]));
    BOOST_CHECK_NE(
        gf::Canonical(
            row.calls[0].input[alg_hash::kAlgHashRate + 1]),
        gf::Canonical(
            fs.calls[0].input[alg_hash::kAlgHashRate + 1]));
}

BOOST_AUTO_TEST_CASE(
    typed_hash_rejects_unregistered_role)
{
    const auto invalid = TypedSpongeHashFpV1(
        static_cast<TypedHashRoleV1>(0), {gf::FromU64(1)});
    BOOST_CHECK(!invalid.valid);
    BOOST_CHECK(invalid.calls.empty());
    const auto fixed_width_must_not_enter_generic_sponge =
        TypedSpongeHashFpV1(
            TypedHashRoleV1::MerkleInternalNode,
            {gf::FromU64(1)});
    BOOST_CHECK(!fixed_width_must_not_enter_generic_sponge.valid);
    BOOST_CHECK(fixed_width_must_not_enter_generic_sponge.calls.empty());
}

BOOST_AUTO_TEST_CASE(
    typed_add_absorb_squares_one_global_shared_permutation_budget)
{
    SharedPermutationBudgetV1 budget;
    budget.proof_sites = 37'488'397;
    budget.fs_permutation_calls_per_site = 1U << 20;
    budget.merkle_permutation_calls_per_site = 1U << 20;
    budget.receipt_program_calls_per_site = 1U << 18;
    budget.adversary_permutation_queries_per_site = 1U << 20;
    budget.exact_manifest_derived = false;

    const auto audit = AssessTypedAddAbsorbHybridV1(budget);
    BOOST_CHECK_GT(audit.goldilocks_bits, 63.0);
    BOOST_CHECK_GT(audit.shared_permutation_queries_log2, 46.0);
    BOOST_CHECK_LT(audit.shared_permutation_queries_log2, 48.0);
    BOOST_CHECK_GT(
        audit.generic_capacity_first_collision_bits, 150.0);
    BOOST_CHECK_GT(
        audit.poseidon_algebraic_floor_after_site_union_bits, 102.0);
    BOOST_CHECK_LT(
        audit.poseidon_algebraic_floor_after_site_union_bits, 104.0);
    BOOST_CHECK_EQUAL(
        audit.effective_first_collision_bits,
        audit.poseidon_algebraic_floor_after_site_union_bits);
    BOOST_CHECK(
        audit.all_shared_permutation_queries_summed_before_square);
    BOOST_CHECK(
        audit.adaptive_multiblock_capacity_collisions_accounted);
    BOOST_CHECK(audit.typed_initial_role_ivs_disjoint);
    BOOST_CHECK(audit.ten_star_message_encoding_prefix_free);
    BOOST_CHECK(
        audit.add_absorb_next_input_injective_given_prior_state);
    BOOST_CHECK(
        audit.concrete_poseidon_ideal_permutation_assumption_disclosed);
    BOOST_CHECK(!audit.custom_reduction_formally_complete);
    BOOST_CHECK(!audit.exact_global_call_manifest_enforced);
    BOOST_CHECK(!audit.active_native_transcript_matches);
    BOOST_CHECK(!audit.recursive_air_transcript_matches);
    BOOST_CHECK(audit.gpu_friendly_poseidon_preserved);
    BOOST_CHECK(audit.numeric_v1_security_screen_met);
    BOOST_CHECK(!audit.production_theorem_complete);
    BOOST_CHECK_GE(audit.assumptions.size(), 4U);
}

BOOST_AUTO_TEST_CASE(
    typed_add_absorb_zero_budget_fails_closed)
{
    const auto audit =
        AssessTypedAddAbsorbHybridV1(SharedPermutationBudgetV1{});
    BOOST_CHECK_EQUAL(audit.shared_permutation_queries_log2, 0.0);
    BOOST_CHECK_EQUAL(
        audit.generic_capacity_first_collision_bits, 0.0);
    BOOST_CHECK_EQUAL(audit.effective_first_collision_bits, 0.0);
    BOOST_CHECK(
        !audit.all_shared_permutation_queries_summed_before_square);
    BOOST_CHECK(!audit.numeric_v1_security_screen_met);
    BOOST_CHECK(!audit.production_theorem_complete);
}

BOOST_AUTO_TEST_CASE(
    published_overwrite_dsfs_delta_is_explicit_and_fail_closed)
{
    const auto audit = AssessOverwriteDuplexFsV1();
    BOOST_CHECK_EQUAL(audit.minimum_capacity_lanes, 4U);
    BOOST_CHECK_EQUAL(audit.persistent_duplex_state_lanes, 12U);
    BOOST_CHECK_EQUAL(
        audit.poseidon_air_columns_per_parameter_set, 484U);
    BOOST_CHECK_EQUAL(audit.minimum_independent_oracle_families, 3U);
    BOOST_CHECK_EQUAL(
        audit.additional_poseidon_parameter_sets_vs_v11, 2U);
    BOOST_CHECK(audit.published_transform_is_overwrite_mode);
    BOOST_CHECK(audit.published_start_capacity_is_instance_derived);
    BOOST_CHECK(
        audit.published_bcs_keeps_merkle_compression_separate);
    BOOST_CHECK(!audit.current_v11_add_absorb_matches);
    BOOST_CHECK(!audit.current_v11_zero_capacity_start_matches);
    BOOST_CHECK(
        !audit.same_parameter_set_domain_tags_are_proven_independent);
    BOOST_CHECK(
        !audit.independent_start_fs_merkle_parameter_sets_executable);
    BOOST_CHECK(!audit.native_overwrite_transcript_executable);
    BOOST_CHECK(!audit.recursive_overwrite_transcript_executable);
    BOOST_CHECK(audit.gpu_friendly_if_poseidon_parameter_sets_added);
    BOOST_CHECK(!audit.published_dsfs_premises_instantiated);
    BOOST_CHECK(!audit.production_theorem_complete);
    BOOST_CHECK_GE(audit.assumptions.size(), 4U);
}

BOOST_AUTO_TEST_CASE(
    v12_path_recommendation_is_not_a_readiness_flip)
{
    SharedPermutationBudgetV1 budget;
    budget.proof_sites = 994'229;
    budget.fs_permutation_calls_per_site = 424;
    budget.merkle_permutation_calls_per_site = 1024;
    budget.receipt_program_calls_per_site = 128;
    budget.adversary_permutation_queries_per_site = 1U << 20;
    budget.safe_tag_hash_queries = 64;
    budget.adversarial_h_query_budget_log2 = 64.0;
    budget.adversarial_permutation_query_budget_log2 = 64.0;
    budget.exact_manifest_derived = true;
    const auto comparison =
        CompareNiropPathsV1(Statement(), budget);
    BOOST_CHECK(
        comparison.recommended ==
        RecommendedNiropPathV1::PublishedSafeCore);
    BOOST_CHECK(
        comparison.recommendation_preserves_current_gpu_poseidon_path);
    BOOST_CHECK(!comparison.recommendation_is_production_selectable);
    BOOST_CHECK(
        comparison.typed_add_absorb.numeric_v1_security_screen_met);
    BOOST_CHECK(
        comparison.typed_add_absorb.exact_global_call_manifest_enforced);
    BOOST_CHECK(
        !comparison.typed_add_absorb.custom_reduction_formally_complete);
    BOOST_CHECK(
        !comparison.overwrite_duplex.published_dsfs_premises_instantiated);
    BOOST_CHECK(
        comparison.safe_core.theorem2_numeric_v1_screen_met);
    BOOST_CHECK(
        !comparison.safe_core.published_safecore_premises_instantiated);
}

BOOST_AUTO_TEST_CASE(
    safecore_line_by_line_mismatch_and_full_capacity_route)
{
    SharedPermutationBudgetV1 budget;
    budget.proof_sites = 994'229;
    budget.fs_permutation_calls_per_site = 424;
    budget.merkle_permutation_calls_per_site = 1024;
    budget.receipt_program_calls_per_site = 128;
    budget.adversary_permutation_queries_per_site = 1U << 20;
    budget.safe_tag_hash_queries = 64;
    budget.adversarial_h_query_budget_log2 = 64.0;
    budget.adversarial_permutation_query_budget_log2 = 64.0;
    budget.exact_manifest_derived = false;
    const auto audit =
        AssessSafeCoreMigrationV1(Statement(), budget);
    BOOST_CHECK_EQUAL(audit.rate_lanes, 8U);
    BOOST_CHECK_EQUAL(audit.capacity_lanes, 4U);
    BOOST_CHECK_EQUAL(audit.width_lanes, 12U);
    BOOST_CHECK_EQUAL(audit.safe_api_spec_tag_lanes, 2U);
    BOOST_CHECK_EQUAL(audit.proved_safecore_tag_lanes, 4U);
    BOOST_CHECK_LT(audit.safe_api_spec_query_ceiling_bits, 64.0);
    BOOST_CHECK_GT(
        audit.proved_safecore_query_ceiling_bits, 127.0);
    BOOST_CHECK(!audit.safe_api_two_lane_profile_meets_v1_screen);
    BOOST_CHECK_EQUAL(audit.v11_transcript_hash_events, 424U);
    BOOST_CHECK_EQUAL(
        audit.proposed_safe_io_absorb_squeeze_events, 424U);
    BOOST_CHECK_EQUAL(audit.honest_tag_hash_queries, 64U);
    BOOST_CHECK_EQUAL(
        audit.theorem_unique_h_queries,
        std::numeric_limits<uint64_t>::max());
    BOOST_CHECK_GE(audit.theorem_h_queries_log2, 64.0);
    BOOST_CHECK_GE(
        audit.theorem_unique_permutation_queries_log2, 64.0);
    BOOST_CHECK(audit.adversarial_classical_query_budgets_included);
    BOOST_CHECK(audit.theorem2_bound_computed);
    BOOST_CHECK_GT(audit.theorem_indifferentiability_bits, 64.0);
    BOOST_CHECK_EQUAL(
        audit.conditional_poseidon_algebraic_floor_bits, 128.0);
    BOOST_CHECK_GT(audit.conditional_effective_bits, 120.0);
    BOOST_CHECK_LT(audit.conditional_effective_bits, 128.0);
    BOOST_CHECK(audit.theorem2_numeric_v1_screen_met);

    BOOST_CHECK(audit.current_v11_resets_state_per_hash_event);
    BOOST_CHECK(!audit.current_v11_is_one_continuous_safe_state);
    BOOST_CHECK(
        !audit.current_v11_capacity_is_full_h_io_domain_tag);
    BOOST_CHECK(!audit.current_v11_io_pattern_fixed_and_enforced);
    BOOST_CHECK(!audit.current_v11_padding_matches_safecore_pad);
    BOOST_CHECK(
        !audit.typed_v12_static_iv_is_full_h_io_domain_tag);

    BOOST_CHECK(audit.proposed_stateless_safecore_per_hash_event);
    BOOST_CHECK(
        audit.proposed_seed_feedback_is_ordinary_message_data);
    BOOST_CHECK(audit.proposed_safecore_zero_padding_fixed_by_io);
    BOOST_CHECK(
        !audit.proposed_fs_is_one_continuous_absorb_squeeze_state);
    BOOST_CHECK(audit.proposed_fs_has_fixed_io_pattern);
    BOOST_CHECK(!audit.proposed_native_seed_feedback_removed);
    BOOST_CHECK(audit.proposed_merkle_instances_have_separate_tags);
    BOOST_CHECK(
        audit.proposed_receipt_program_instances_have_separate_tags);
    BOOST_CHECK(audit.proposed_uses_full_capacity_tag);
    BOOST_CHECK(audit.proposed_tag_hash_to_fp4_is_canonical);
    BOOST_CHECK(!audit.proposed_tag_registry_root_pinned);
    BOOST_CHECK(!audit.exact_safe_io_pattern_manifest_enforced);
    BOOST_CHECK(!audit.native_safe_transcript_executable);
    BOOST_CHECK(!audit.recursive_safe_transcript_executable);
    BOOST_CHECK(audit.gpu_friendly_poseidon_preserved);
    BOOST_CHECK(audit.tag_hash_random_oracle_assumption_disclosed);
    BOOST_CHECK(
        audit.poseidon_random_permutation_assumption_disclosed);
    BOOST_CHECK(!audit.concrete_tag_hash_reduction_complete);
    BOOST_CHECK(!audit.concrete_poseidon_reduction_complete);
    BOOST_CHECK(!audit.published_safecore_premises_instantiated);
    BOOST_CHECK(!audit.production_theorem_complete);
    BOOST_CHECK_GE(audit.premise_mismatches.size(), 5U);
    BOOST_CHECK_GE(audit.required_protocol_changes.size(), 5U);
}

BOOST_AUTO_TEST_CASE(
    safecore_missing_global_query_manifest_fails_closed)
{
    SharedPermutationBudgetV1 no_queries;
    no_queries.proof_sites = 1;
    const auto audit =
        AssessSafeCoreMigrationV1(Statement(), no_queries);
    BOOST_CHECK(!audit.theorem2_bound_computed);
    BOOST_CHECK_EQUAL(
        audit.theorem_indifferentiability_bits, 0.0);
    BOOST_CHECK(!audit.theorem2_numeric_v1_screen_met);
    BOOST_CHECK(!audit.published_safecore_premises_instantiated);
    BOOST_CHECK(!audit.production_theorem_complete);
}

BOOST_AUTO_TEST_CASE(
    safe_q192_v13_computes_one_shared_oracle_composition)
{
    SafeQ192QueryBudgetV13 budget;
    budget.honest_h_queries = 37'488'397;
    budget.honest_poseidon_queries = 994'229ULL * 2048ULL;
    budget.adversarial_h_queries_log2 = 64.0;
    budget.adversarial_poseidon_queries_log2 = 64.0;
    budget.exact_manifest_derived = true;

    SafeQ192ReductionPremisesV13 premises;
    premises.exact_typed_io_domain_program = true;
    premises.domain_registry_root_rebuilt_and_pinned = true;
    premises.native_safe_q192_transcript_executable = true;
    premises.native_safe_q192_verifier_replays_transcript = true;
    premises.recursive_safe_event_parent_proved = true;
    premises.every_recursive_message_cell_authenticated = true;
    premises.every_recursive_output_cell_consumed = true;
    premises.canonical_query_seed_is_sole_query_source = true;
    premises.exact_global_h_p_manifest_enforced = true;
    premises.all_shared_poseidon_calls_counted_before_square = true;
    premises.typed_commitment_encodings_injective = true;
    premises.native_recursive_poseidon_parity = true;
    premises.adaptive_statement_and_oracle_queries_accounted = true;
    premises.sha256d_random_oracle_assumption_accepted = true;
    premises.poseidon2_ideal_permutation_assumption_accepted = true;

    const auto audit =
        AssessSafeQ192ReductionV13(budget, premises);
    BOOST_CHECK_EQUAL(audit.protocol_version, 13U);
    BOOST_CHECK_EQUAL(audit.queries, 192U);
    BOOST_CHECK_EQUAL(audit.ood_candidates, 2U);
    BOOST_CHECK_EQUAL(audit.rate_lanes, 8U);
    BOOST_CHECK_EQUAL(audit.capacity_lanes, 4U);
    BOOST_CHECK_EQUAL(audit.width_lanes, 12U);
    BOOST_CHECK_EQUAL(audit.typed_role_count, 20U);
    BOOST_CHECK(audit.canonical_v13_parameters);
    BOOST_CHECK(
        audit.full_capacity_joint_rejection_tag_executable);
    BOOST_CHECK_GE(audit.total_h_queries_log2, 64.0);
    BOOST_CHECK_GE(audit.total_poseidon_queries_log2, 64.0);
    BOOST_CHECK(audit.safecore_theorem2_bound_computed);
    BOOST_CHECK(
        audit.shared_permutation_first_collision_bound_computed);
    BOOST_CHECK_GT(
        audit.safecore_indifferentiability_bits, 120.0);
    BOOST_CHECK_GT(
        audit.commitment_first_collision_bits, 120.0);
    BOOST_CHECK_GT(audit.composed_computational_bits, 120.0);
    BOOST_CHECK_LT(audit.composed_computational_bits, 128.0);
    BOOST_CHECK(audit.no_independent_domain_lane_claim);
    BOOST_CHECK(audit.adversarial_classical_budgets_included);
    BOOST_CHECK(audit.concrete_assumptions_explicit);
    BOOST_CHECK(audit.numeric_v1_screen_met);
    BOOST_CHECK(audit.oracle_separation_reduction_complete);
    BOOST_CHECK(audit.commitment_binding_reduction_complete);
    BOOST_CHECK(audit.production_composition_complete);
    BOOST_CHECK(audit.missing_premises.empty());
}

BOOST_AUTO_TEST_CASE(
    safe_q192_v13_exact_per_proof_h_p_and_query_inventory)
{
    const uint256 seed = V13Seed(0x91);
    const auto proved = Fri3AlgSafeQ192K2V13BatchCommit(
        V13Columns(), seed, 13);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);

    V13PerProofOracleInventoryV1 native;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildV13PerProofOracleInventoryV1(
            proved.proof, seed, native, &why),
        why);
    BOOST_CHECK(native.native_proof_accepted);
    BOOST_CHECK(native.exact_event_order);
    BOOST_CHECK(native.every_h_rejection_attempt_counted);
    BOOST_CHECK(native.every_shared_p_occurrence_counted);
    BOOST_CHECK(native.ordered_h_domains_bound);
    BOOST_CHECK(native.p_states_canonical_and_executable);
    BOOST_CHECK(
        native.canonical_query_seed_is_sole_query_source);
    BOOST_CHECK(native.exact_per_proof_inventory);
    BOOST_CHECK(!native.native_recursive_inputs_equal);
    BOOST_CHECK(
        !native.recursive_air_authenticates_parity_inputs);
    BOOST_CHECK(!native.exact_global_topology_inventory);
    BOOST_CHECK(!native.production_nirop_complete);
    BOOST_CHECK_GE(native.residual_premises.size(), 4U);
    BOOST_CHECK_EQUAL(native.protocol_version, 13U);
    BOOST_CHECK_EQUAL(native.width, 2U);
    BOOST_CHECK_EQUAL(native.n_coeffs, 8U);
    BOOST_CHECK_EQUAL(native.n_lde, 128U);
    BOOST_CHECK_EQUAL(native.folds, 3U);
    BOOST_CHECK_EQUAL(native.queries, kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(
        native.accepted_h_candidates,
        native.query_events.size());
    BOOST_CHECK_EQUAL(
        native.h_calls.size(),
        native.accepted_h_candidates +
            native.rejected_h_candidates);
    BOOST_CHECK_EQUAL(
        native.p_calls.size(),
        native.safe_p_calls +
            native.commitment_p_calls +
            native.merkle_p_calls);
    BOOST_CHECK_GT(native.safe_p_calls, 0U);
    BOOST_CHECK_GT(native.commitment_p_calls, 0U);
    BOOST_CHECK_GT(native.merkle_p_calls, 0U);
    BOOST_TEST_MESSAGE(
        "V13_EXACT_ORACLE_INVENTORY h="
        << native.h_calls.size()
        << " h_rejected=" << native.rejected_h_candidates
        << " p=" << native.p_calls.size()
        << " p_safe=" << native.safe_p_calls
        << " p_commitment=" << native.commitment_p_calls
        << " p_merkle=" << native.merkle_p_calls
        << " transcript_events=" << native.query_events.size());

    for (uint64_t i = 0; i < native.h_calls.size(); ++i) {
        BOOST_CHECK_EQUAL(native.h_calls[i].occurrence, i);
    }
    for (uint64_t i = 0; i < native.p_calls.size(); ++i) {
        BOOST_CHECK_EQUAL(native.p_calls[i].occurrence, i);
    }
    for (uint32_t i = 0; i < native.query_events.size(); ++i) {
        BOOST_CHECK_EQUAL(native.query_events[i].occurrence, i);
    }

    V13RecursiveOracleParityInputsV1 recursive{
        native.h_calls, native.p_calls, native.query_events};
    V13PerProofOracleInventoryV1 parity;
    BOOST_REQUIRE_MESSAGE(
        ValidateV13NativeRecursiveOracleParityV1(
            proved.proof, seed, recursive, parity, &why),
        why);
    BOOST_CHECK(parity.native_recursive_inputs_equal);
    BOOST_CHECK(parity.exact_per_proof_inventory);
    BOOST_CHECK(
        !parity.recursive_air_authenticates_parity_inputs);
    BOOST_CHECK(!parity.exact_global_topology_inventory);
    BOOST_CHECK(!parity.production_nirop_complete);
}

BOOST_AUTO_TEST_CASE(
    safe_q192_v13_inventory_rejects_all_manifest_mutations)
{
    const uint256 seed = V13Seed(0xa1);
    const auto proved = Fri3AlgSafeQ192K2V13BatchCommit(
        V13Columns(), seed, 17);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    V13PerProofOracleInventoryV1 native;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildV13PerProofOracleInventoryV1(
            proved.proof, seed, native, &why),
        why);
    const V13RecursiveOracleParityInputsV1 exact{
        native.h_calls, native.p_calls, native.query_events};
    const auto rejects =
        [&](V13RecursiveOracleParityInputsV1 changed) {
            V13PerProofOracleInventoryV1 rejected;
            BOOST_CHECK(
                !ValidateV13NativeRecursiveOracleParityV1(
                    proved.proof, seed, changed,
                    rejected, &why));
            BOOST_CHECK(!rejected.native_recursive_inputs_equal);
            BOOST_CHECK(!rejected.production_nirop_complete);
        };

    {
        auto changed = exact;
        changed.h_calls.erase(changed.h_calls.begin() + 1);
        for (uint64_t i = 0; i < changed.h_calls.size(); ++i) {
            changed.h_calls[i].occurrence = i;
        }
        rejects(std::move(changed));
    }
    {
        auto changed = exact;
        auto duplicate = changed.p_calls.back();
        duplicate.occurrence = changed.p_calls.size();
        changed.p_calls.push_back(std::move(duplicate));
        rejects(std::move(changed));
    }
    {
        auto changed = exact;
        BOOST_REQUIRE_GE(changed.query_events.size(), 2U);
        std::swap(
            changed.query_events[0],
            changed.query_events[1]);
        changed.query_events[0].occurrence = 0;
        changed.query_events[1].occurrence = 1;
        rejects(std::move(changed));
    }
    {
        auto changed = exact;
        const auto item = std::find_if(
            changed.p_calls.begin(), changed.p_calls.end(),
            [](const V13POracleCallV1& call) {
                return call.family ==
                    V13POracleFamilyV1::TerminalLeaf;
            });
        BOOST_REQUIRE(item != changed.p_calls.end());
        changed.p_calls.erase(item);
        for (uint64_t i = 0; i < changed.p_calls.size(); ++i) {
            changed.p_calls[i].occurrence = i;
        }
        rejects(std::move(changed));
    }
    {
        auto changed = exact;
        BOOST_REQUIRE(!changed.h_calls.front().typed_domain.empty());
        changed.h_calls.front().typed_domain.back() ^= 1U;
        rejects(std::move(changed));
    }
    {
        auto changed = exact;
        bool changed_zero = false;
        for (auto& call : changed.p_calls) {
            const auto zero =
                std::find(call.input.begin(), call.input.end(), 0);
            if (zero == call.input.end()) continue;
            *zero = gf::kP;
            changed_zero = true;
            break;
        }
        BOOST_REQUIRE(changed_zero);
        rejects(std::move(changed));
    }
    {
        auto changed = exact;
        ++changed.h_calls.front().rejection_counter;
        rejects(std::move(changed));
    }

    {
        const uint256 other_seed = V13Seed(0xb1);
        const auto other = Fri3AlgSafeQ192K2V13BatchCommit(
            V13Columns(1000), other_seed, 19);
        BOOST_REQUIRE_MESSAGE(other.ok, other.note);
        V13PerProofOracleInventoryV1 other_native;
        BOOST_REQUIRE_MESSAGE(
            BuildV13PerProofOracleInventoryV1(
                other.proof, other_seed,
                other_native, &why),
            why);
        rejects({
            other_native.h_calls,
            other_native.p_calls,
            other_native.query_events});
    }
}

BOOST_AUTO_TEST_CASE(
    safe_q192_v13_every_production_premise_fails_closed)
{
    SafeQ192QueryBudgetV13 budget;
    budget.honest_h_queries = 1;
    budget.honest_poseidon_queries = 1;
    budget.adversarial_h_queries_log2 = 64.0;
    budget.adversarial_poseidon_queries_log2 = 64.0;
    budget.exact_manifest_derived = true;

    SafeQ192ReductionPremisesV13 all;
    all.exact_typed_io_domain_program = true;
    all.domain_registry_root_rebuilt_and_pinned = true;
    all.native_safe_q192_transcript_executable = true;
    all.native_safe_q192_verifier_replays_transcript = true;
    all.recursive_safe_event_parent_proved = true;
    all.every_recursive_message_cell_authenticated = true;
    all.every_recursive_output_cell_consumed = true;
    all.canonical_query_seed_is_sole_query_source = true;
    all.exact_global_h_p_manifest_enforced = true;
    all.all_shared_poseidon_calls_counted_before_square = true;
    all.typed_commitment_encodings_injective = true;
    all.native_recursive_poseidon_parity = true;
    all.adaptive_statement_and_oracle_queries_accounted = true;
    all.sha256d_random_oracle_assumption_accepted = true;
    all.poseidon2_ideal_permutation_assumption_accepted = true;
    BOOST_REQUIRE(
        AssessSafeQ192ReductionV13(budget, all)
            .production_composition_complete);

    const auto rejects = [&](const auto& mutate) {
        auto changed = all;
        mutate(changed);
        const auto audit =
            AssessSafeQ192ReductionV13(budget, changed);
        BOOST_CHECK(!audit.production_composition_complete);
        BOOST_CHECK(!audit.missing_premises.empty());
    };
    rejects([](auto& p) {
        p.exact_typed_io_domain_program = false;
    });
    rejects([](auto& p) {
        p.domain_registry_root_rebuilt_and_pinned = false;
    });
    rejects([](auto& p) {
        p.native_safe_q192_transcript_executable = false;
    });
    rejects([](auto& p) {
        p.native_safe_q192_verifier_replays_transcript = false;
    });
    rejects([](auto& p) {
        p.recursive_safe_event_parent_proved = false;
    });
    rejects([](auto& p) {
        p.every_recursive_message_cell_authenticated = false;
    });
    rejects([](auto& p) {
        p.every_recursive_output_cell_consumed = false;
    });
    rejects([](auto& p) {
        p.canonical_query_seed_is_sole_query_source = false;
    });
    rejects([](auto& p) {
        p.exact_global_h_p_manifest_enforced = false;
    });
    rejects([](auto& p) {
        p.all_shared_poseidon_calls_counted_before_square = false;
    });
    rejects([](auto& p) {
        p.typed_commitment_encodings_injective = false;
    });
    rejects([](auto& p) {
        p.native_recursive_poseidon_parity = false;
    });
    rejects([](auto& p) {
        p.adaptive_statement_and_oracle_queries_accounted = false;
    });
    rejects([](auto& p) {
        p.sha256d_random_oracle_assumption_accepted = false;
    });
    rejects([](auto& p) {
        p.poseidon2_ideal_permutation_assumption_accepted = false;
    });

    auto no_manifest = budget;
    no_manifest.exact_manifest_derived = false;
    const auto missing_manifest =
        AssessSafeQ192ReductionV13(no_manifest, all);
    BOOST_CHECK(
        !missing_manifest.production_composition_complete);
    BOOST_CHECK(!missing_manifest.missing_premises.empty());

    auto underbudget = budget;
    underbudget.adversarial_h_queries_log2 = 63.0;
    const auto missing_attacker_budget =
        AssessSafeQ192ReductionV13(underbudget, all);
    BOOST_CHECK(
        !missing_attacker_budget
             .adversarial_classical_budgets_included);
    BOOST_CHECK(
        !missing_attacker_budget.production_composition_complete);
}

BOOST_AUTO_TEST_CASE(
    safe_q192_v13_zero_queries_and_invalid_floors_reject)
{
    SafeQ192QueryBudgetV13 empty;
    SafeQ192ReductionPremisesV13 none;
    const auto no_queries =
        AssessSafeQ192ReductionV13(empty, none);
    BOOST_CHECK(!no_queries.safecore_theorem2_bound_computed);
    BOOST_CHECK(
        !no_queries.shared_permutation_first_collision_bound_computed);
    BOOST_CHECK_EQUAL(no_queries.composed_computational_bits, 0.0);
    BOOST_CHECK(!no_queries.production_composition_complete);

    SafeQ192QueryBudgetV13 one;
    one.honest_h_queries = 1;
    one.honest_poseidon_queries = 1;
    one.exact_manifest_derived = true;
    auto assumptions = none;
    assumptions.sha256d_random_oracle_assumption_accepted = true;
    assumptions.poseidon2_ideal_permutation_assumption_accepted = true;
    const auto zero_floor =
        AssessSafeQ192ReductionV13(
            one, assumptions, 0.0, 128.0);
    BOOST_CHECK(
        !zero_floor.adversarial_classical_budgets_included);
    BOOST_CHECK(!zero_floor.concrete_assumptions_explicit);
    BOOST_CHECK_EQUAL(zero_floor.composed_computational_bits, 0.0);
    BOOST_CHECK(!zero_floor.production_composition_complete);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_nirop_hybrid
