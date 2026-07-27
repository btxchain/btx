// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_nirop_hybrid.h>

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

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_nirop_hybrid
