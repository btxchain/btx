// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_semantic_alg.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>
#include <vector>

namespace alg =
    matmul::v4::rc::episode_semantic_alg;
namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_episode_semantic_alg_tests,
    BasicTestingSetup)

namespace {

uint256 Filled(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

std::vector<gf::Fp3> Values()
{
    return {
        gf::FromU64_3(3),
        gf::FromU64_3(5),
        gf::FromU64_3(8),
        gf::FromU64_3(13),
        gf::FromU64_3(21),
    };
}

alg::BundleV2 Prove()
{
    const auto values = Values();
    const uint256 root =
        rc::RCStage3VectorRootAlgCommitment(values);
    alg::BundleV2 out;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        alg::ProveBundleWithOwningValuesV2(
            rc::RCStage3RelationEndpoint::
                EpisodeGemmOperandA,
            7, Filled(0x51), root, values,
            out, &why),
        why);
    return out;
}

alg::VerificationAuditV2 Verify(
    const alg::BundleV2& bundle)
{
    const auto values = Values();
    return alg::VerifyBundleWithOwningValuesV2(
        rc::RCStage3RelationEndpoint::
            EpisodeGemmOperandA,
        7, Filled(0x51),
        rc::RCStage3VectorRootAlgCommitment(values),
        values, bundle);
}

} // namespace

BOOST_AUTO_TEST_CASE(
    canonical_program_and_expected_cs_proof_seed_interface)
{
    const auto bundle = Prove();
    BOOST_REQUIRE_EQUAL(bundle.leaves.size(), 1U);
    const auto& receipt = bundle.leaves[0];

    rc::constraint_bytecode::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        alg::BuildCanonicalProgramTableV2(
            receipt.manifest.endpoint, table, &why),
        why);
    BOOST_CHECK_EQUAL(
        table.current_width,
        rc::kRCStage3EpisodeMemoryColumns);
    BOOST_CHECK(
        rc::constraint_bytecode::CommitProgramTable(table) ==
        receipt.manifest.program_table_sha256d);
    BOOST_CHECK(
        rc::Fri3AlgDigestToUint256(
            rc::constraint_bytecode::
                CommitProgramTableAlgHash(table)) ==
        receipt.manifest.program_table_alg);

    const auto input =
        alg::BuildVerificationInputV2(receipt);
    BOOST_REQUIRE_MESSAGE(input.valid, input.note);
    BOOST_REQUIRE(input.proof != nullptr);
    BOOST_CHECK_EQUAL(
        input.expected_cs.n_columns,
        rc::kRCStage3EpisodeMemoryColumns);
    BOOST_CHECK(
        input.expected_base_column_indices ==
        alg::CanonicalBaseColumnsV2());
    BOOST_CHECK(
        input.public_fs_seed ==
        receipt.public_fs_seed);
    BOOST_CHECK(
        input.expected_cs_commitment ==
        receipt.manifest.expected_cs_commitment);
    BOOST_REQUIRE_EQUAL(
        input.expected_cs
            .preprocessed_row_group_roots.size(),
        1U);
    BOOST_CHECK(
        input.expected_cs
            .preprocessed_row_group_roots[0].root ==
        receipt.manifest.authority_r0_root);

    const auto audit = Verify(bundle);
    BOOST_REQUIRE_MESSAGE(audit.accepted, audit.note);
    BOOST_CHECK(audit.canonical_program_table);
    BOOST_CHECK(audit.exact_partition);
    BOOST_CHECK(audit.exact_addresses);
    BOOST_CHECK(
        audit.all_safe_split_rap_proofs_verified);
    BOOST_CHECK(audit.host_owning_values_bound);
    BOOST_CHECK(!audit.normalized_recursive_source);
    BOOST_CHECK(!audit.recursively_consumed);

    const auto receipt_only = alg::VerifyBundleV2(
        bundle.endpoint, bundle.layer_ordinal,
        bundle.statement_commitment,
        bundle.total_instance_count,
        bundle.producer_vector_root_alg, bundle);
    BOOST_REQUIRE_MESSAGE(
        receipt_only.accepted, receipt_only.note);
    BOOST_CHECK(
        receipt_only
            .all_safe_split_rap_proofs_verified);
    BOOST_CHECK(
        !receipt_only.host_owning_values_bound);
    BOOST_CHECK(
        !receipt_only.normalized_recursive_source);
}

BOOST_AUTO_TEST_CASE(
    omission_transplant_and_program_identity_attacks_reject)
{
    const auto honest = Prove();

    auto omitted = honest;
    omitted.leaves.clear();
    omitted.exact_all_instance_commitment =
        Filled(0x11);
    omitted.bundle_commitment =
        alg::ComputeBundleCommitmentV2(omitted);
    BOOST_CHECK(!Verify(omitted).accepted);

    auto transplanted = honest;
    transplanted.endpoint =
        rc::RCStage3RelationEndpoint::
            EpisodeGemmOperandB;
    transplanted.bundle_commitment =
        alg::ComputeBundleCommitmentV2(transplanted);
    const auto transplant_audit =
        alg::VerifyBundleV2(
            rc::RCStage3RelationEndpoint::
                EpisodeGemmOperandB,
            7, Filled(0x51),
            transplanted.total_instance_count,
            transplanted.producer_vector_root_alg,
            transplanted);
    BOOST_CHECK(!transplant_audit.accepted);

    auto wrong_program = honest;
    wrong_program.leaves[0]
        .manifest.program_table_sha256d =
        Filled(0x22);
    BOOST_CHECK(
        !alg::ValidateLeafManifestV2(
            wrong_program.leaves[0].manifest));

    auto wrong_address = honest;
    ++wrong_address.leaves[0]
          .manifest.address_begin;
    BOOST_CHECK(
        !alg::ValidateLeafManifestV2(
            wrong_address.leaves[0].manifest));
}

BOOST_AUTO_TEST_CASE(
    proof_query_r0_root_and_owning_value_attacks_reject)
{
    const auto honest = Prove();
    const auto verification_input =
        alg::BuildVerificationInputV2(
            honest.leaves[0]);
    BOOST_REQUIRE_MESSAGE(
        verification_input.valid,
        verification_input.note);

    auto query = honest;
    BOOST_REQUIRE(
        !query.leaves[0]
             .proof.batch.queries.empty());
    BOOST_REQUIRE(
        !query.leaves[0]
             .proof.batch.queries[0]
             .group_rows.empty());
    BOOST_REQUIRE(
        !query.leaves[0]
             .proof.batch.queries[0]
             .group_rows[0].values.empty());
    query.leaves[0]
        .proof.batch.queries[0]
        .group_rows[0].values[0].c0 =
        gf::Add(
            query.leaves[0]
                .proof.batch.queries[0]
                .group_rows[0].values[0].c0,
            gf::FromU64(1));
    std::string proof_why;
    BOOST_CHECK(
        !rc::air_quotient::
            AirQuotientVerifyRowsSplitRapSafeV2(
                verification_input.expected_cs,
                query.leaves[0].proof,
                verification_input
                    .expected_base_column_indices,
                verification_input.public_fs_seed,
                &proof_why));
    BOOST_CHECK(!Verify(query).accepted);

    auto root = honest;
    root.leaves[0]
        .proof.batch.groups[0]
        .row_commit.root[0] =
        gf::Add(
            root.leaves[0]
                .proof.batch.groups[0]
                .row_commit.root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !rc::air_quotient::
            AirQuotientVerifyRowsSplitRapSafeV2(
                verification_input.expected_cs,
                root.leaves[0].proof,
                verification_input
                    .expected_base_column_indices,
                verification_input.public_fs_seed,
                &proof_why));
    BOOST_CHECK(!Verify(root).accepted);

    auto changed_values = Values();
    changed_values[2] =
        gf::Add(changed_values[2], gf::Fp3::One());
    const auto source_audit =
        alg::VerifyBundleWithOwningValuesV2(
            honest.endpoint, honest.layer_ordinal,
            honest.statement_commitment,
            honest.producer_vector_root_alg,
            changed_values, honest);
    BOOST_CHECK(!source_audit.accepted);
}

BOOST_AUTO_TEST_SUITE_END()
