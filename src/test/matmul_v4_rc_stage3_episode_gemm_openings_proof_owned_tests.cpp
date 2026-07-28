// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_episode_gemm_openings_proof_owned.h>

namespace owned =
    matmul::v4::rc::episode_gemm_openings_proof_owned;
namespace gf = matmul::v4::rc::gkr_field;
namespace topo = matmul::v4::rc::universal_topology;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_episode_gemm_openings_proof_owned_tests)

namespace {

uint256 Root(uint32_t tag)
{
    uint256 out;
    for (uint32_t index = 0; index < out.size(); ++index) {
        out.begin()[index] =
            static_cast<unsigned char>(
                (tag + 31U * index) & 0xffU);
    }
    if (out.IsNull()) out.begin()[0] = 1;
    return out;
}

std::array<
    std::vector<gf::Fp3>, owned::kEndpointCountV1>
Values()
{
    std::array<
        std::vector<gf::Fp3>, owned::kEndpointCountV1> out;
    for (uint32_t lane = 0;
         lane < owned::kEndpointCountV1; ++lane) {
        const uint32_t count = 5U + lane;
        for (uint32_t row = 0; row < count; ++row) {
            out[lane].push_back(
                gf::FromU64_3(
                    1000U + 101U * lane + row));
        }
    }
    return out;
}

owned::StatementV1 Statement(
    const std::array<
        std::vector<gf::Fp3>,
        owned::kEndpointCountV1>& values)
{
    std::array<
        owned::EndpointStatementV1,
        owned::kEndpointCountV1> endpoints;
    const auto& order = owned::CanonicalEndpointOrderV1();
    for (uint32_t lane = 0;
         lane < owned::kEndpointCountV1; ++lane) {
        endpoints[lane].endpoint = order[lane];
        endpoints[lane].total_instance_count =
            values[lane].size();
        endpoints[lane].address_begin =
            2000U + lane * 100U;
        endpoints[lane].address_stride = lane + 1U;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            owned::ComputeCanonicalShardRootsV1(
                values[lane],
                endpoints[lane].canonical_value_roots,
                &why),
            why);
    }
    owned::StatementV1 out;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        owned::BuildStatementV1(
            Root(0x51), endpoints, out, &why),
        why);
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    exact_a_b_y_proof_owned_bundles_close_source_and_all_instance_residuals)
{
    const auto values = Values();
    const auto statement = Statement(values);
    owned::ProofV1 proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        owned::ProveV1(statement, values, proof, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        owned::VerifyV1(statement, proof, &why),
        why);
    const auto audit = owned::AssessV1(statement, proof);
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK(audit.canonical_family_selected);
    BOOST_CHECK(audit.exact_endpoint_order);
    BOOST_CHECK(audit.exact_shard_partition);
    BOOST_CHECK(audit.every_memory_child_proof_verified);
    BOOST_CHECK(audit.source_roots_proof_owned);
    BOOST_CHECK(audit.exact_all_instance_aggregation);
    BOOST_CHECK(!audit.production_all_instance_aggregation);
    BOOST_CHECK(audit.proof_level_tamper_rejected);
    BOOST_CHECK(!audit.normalized_parent_accepts_sha_children);
    BOOST_CHECK(!audit.cross_hash_value_equality_proved);
    BOOST_CHECK(!audit.recursively_consumed);
    BOOST_CHECK_EQUAL(
        audit.residual_obligations,
        topo::ProductionResidualExactAllInstanceAggregation |
        topo::ProductionResidualRecursiveConsumption);
    BOOST_CHECK(
        !proof.ordered_proof_set_commitment.IsNull());
    for (uint32_t lane = 0;
         lane < owned::kEndpointCountV1; ++lane) {
        BOOST_REQUIRE_EQUAL(
            proof.endpoint_bundles[lane].shards.size(),
            statement.endpoints[lane]
                .canonical_value_roots.size());
        BOOST_CHECK_EQUAL(
            proof.endpoint_bundles[lane]
                .total_instance_count,
            values[lane].size());
    }
}

BOOST_AUTO_TEST_CASE(
    production_a_b_y_counts_are_derived_from_the_site_manifest)
{
    const auto shape = owned::BuildProductionShapeV1();
    BOOST_REQUIRE(shape.exact_manifest_total);
    BOOST_CHECK(
        !shape.site_manifest_commitment.IsNull());
    BOOST_CHECK_GT(shape.total_instances, 0U);
    BOOST_CHECK_EQUAL(
        shape.endpoint_instances[0] +
            shape.endpoint_instances[1] +
            shape.endpoint_instances[2],
        shape.total_instances);

    std::array<
        owned::EndpointStatementV1,
        owned::kEndpointCountV1> endpoints;
    const auto& order = owned::CanonicalEndpointOrderV1();
    for (uint32_t lane = 0;
         lane < owned::kEndpointCountV1; ++lane) {
        endpoints[lane].endpoint = order[lane];
        endpoints[lane].total_instance_count =
            shape.endpoint_instances[lane];
        endpoints[lane].address_begin = 0;
        endpoints[lane].address_stride = 1;
        const uint64_t shards =
            (shape.endpoint_instances[lane] +
             matmul::v4::rc::
                 kRCStage3EpisodeSemanticMaxRows - 1U) /
            matmul::v4::rc::
                kRCStage3EpisodeSemanticMaxRows;
        endpoints[lane].canonical_value_roots.assign(
            static_cast<size_t>(shards),
            Root(0x90 + lane));
    }
    owned::StatementV1 statement;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        owned::BuildStatementV1(
            Root(0x52), endpoints, statement, &why),
        why);
    BOOST_CHECK(statement.production_manifest_counts_bound);
    BOOST_CHECK(
        statement.production_site_manifest_commitment ==
        shape.site_manifest_commitment);

    ++endpoints[0].total_instance_count;
    endpoints[0].canonical_value_roots.assign(
        static_cast<size_t>(
            (endpoints[0].total_instance_count +
             matmul::v4::rc::
                 kRCStage3EpisodeSemanticMaxRows - 1U) /
            matmul::v4::rc::
                kRCStage3EpisodeSemanticMaxRows),
        Root(0xa0));
    owned::StatementV1 nonproduction;
    BOOST_REQUIRE_MESSAGE(
        owned::BuildStatementV1(
            Root(0x52), endpoints, nonproduction, &why),
        why);
    BOOST_CHECK(
        !nonproduction.production_manifest_counts_bound);
    BOOST_CHECK(
        nonproduction
            .production_site_manifest_commitment.IsNull());
}

BOOST_AUTO_TEST_CASE(
    omission_transplant_relabel_root_and_proof_mutation_reject)
{
    const auto values = Values();
    const auto statement = Statement(values);
    owned::ProofV1 proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        owned::ProveV1(statement, values, proof, &why),
        why);

    auto omitted = proof;
    omitted.endpoint_bundles[1].shards.clear();
    omitted.endpoint_bundles[1].bundle_commitment =
        matmul::v4::rc::
            ComputeRCStage3EpisodeSemanticMemoryBundleCommitment(
                omitted.endpoint_bundles[1]);
    omitted.ordered_proof_set_commitment =
        owned::ComputeOrderedProofSetCommitmentV1(omitted);
    BOOST_CHECK(!owned::VerifyV1(
        statement, omitted, &why));

    auto transplanted = proof;
    std::swap(
        transplanted.endpoint_bundles[0],
        transplanted.endpoint_bundles[1]);
    transplanted.ordered_proof_set_commitment =
        owned::ComputeOrderedProofSetCommitmentV1(
            transplanted);
    BOOST_CHECK(!owned::VerifyV1(
        statement, transplanted, &why));

    auto relabelled = statement;
    relabelled.endpoints[0].endpoint =
        relabelled.endpoints[1].endpoint;
    relabelled.statement_commitment =
        owned::ComputeStatementCommitmentV1(relabelled);
    BOOST_CHECK(!owned::VerifyV1(
        relabelled, proof, &why));

    auto wrong_root = statement;
    wrong_root.endpoints[2].canonical_value_roots[0] =
        Root(0xbad);
    wrong_root.statement_commitment =
        owned::ComputeStatementCommitmentV1(wrong_root);
    BOOST_CHECK(!owned::VerifyV1(
        wrong_root, proof, &why));

    auto bad_query = proof;
    auto& quotient =
        bad_query.endpoint_bundles[2]
            .shards[0].proof.quotient;
    BOOST_REQUIRE(!quotient.batch.queries.empty());
    BOOST_REQUIRE(
        !quotient.batch.queries[0].columns.empty());
    quotient.batch.queries[0].columns[0].value =
        gf::Add(
            quotient.batch.queries[0]
                .columns[0].value,
            gf::Fp3::One());
    bad_query.endpoint_bundles[2].bundle_commitment =
        matmul::v4::rc::
            ComputeRCStage3EpisodeSemanticMemoryBundleCommitment(
                bad_query.endpoint_bundles[2]);
    bad_query.ordered_proof_set_commitment =
        owned::ComputeOrderedProofSetCommitmentV1(
            bad_query);
    BOOST_CHECK(!owned::VerifyV1(
        statement, bad_query, &why));

    auto wrong_values = values;
    wrong_values[0][0] =
        gf::Add(wrong_values[0][0], gf::Fp3::One());
    owned::ProofV1 rejected;
    BOOST_CHECK(
        !owned::ProveV1(
            statement, wrong_values, rejected, &why));
}

BOOST_AUTO_TEST_SUITE_END()
