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

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_nirop_hybrid
