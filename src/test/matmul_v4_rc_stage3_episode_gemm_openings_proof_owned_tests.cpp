// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_episode_gemm_openings_proof_owned.h>

namespace owned =
    matmul::v4::rc::episode_gemm_openings_proof_owned;
namespace rc = matmul::v4::rc;
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

rc::RCStage3SuccinctProof EpisodeStatement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Episode;
    out.public_inputs.height = 177;
    out.public_inputs.episode_profile = 2;
    out.public_inputs.header_commitment = Root(0x11);
    out.public_inputs.params_commitment = Root(0x12);
    out.public_inputs.target = Root(0x13);
    out.public_inputs.sigma = Root(0x14);
    out.public_inputs.episode_digest = Root(0x15);
    out.public_inputs.final_digest = Root(0x15);
    return out;
}

rc::RCEpisodeParams TinyParams()
{
    rc::RCEpisodeParams out;
    out.rounds = 1;
    out.d_head = 32;
    out.n_q = 32;
    out.n_ctx = 32;
    out.L_lyr = 1;
    out.d_model = 32;
    out.d_ff = 32;
    out.b_seq = 32;
    out.T_leaf = 64;
    return out;
}

std::vector<rc::RCStage3GemmExtractLayerBindings>
Bindings(const rc::RCEpisodeParams& params)
{
    const auto layout = rc::RCGkrTraceLayout(params);
    std::vector<rc::RCStage3GemmExtractLayerBindings> out(
        layout.layers.size());
    for (uint32_t ordinal = 0;
         ordinal < out.size(); ++ordinal) {
        auto& binding = out[ordinal];
        binding.extract_prf = Root(0x20 + ordinal);
        binding.operand_a_root = Root(0x30 + ordinal);
        binding.operand_b_root = Root(0x40 + ordinal);
        binding.gemm_y_root = Root(0x50 + ordinal);
        binding.extract_input_root = Root(0x60 + ordinal);
        binding.extract_output_root = Root(0x70 + ordinal);
        binding.gemm_proof_root = Root(0x80 + ordinal);
        binding.extract_recursive_root = Root(0x90 + ordinal);
        binding.scale_schedule_root = Root(0xa0 + ordinal);
        binding.ctl_terminal_root = Root(0xb0 + ordinal);
    }
    return out;
}

struct OwningFixture {
    rc::RCStage3SuccinctProof outer{EpisodeStatement()};
    rc::RCStage3GemmExtractManifest manifest;
    rc::RCStage3EpisodeGemmProduct gemm;
    rc::RCStage3EpisodeExtractProduct extract;
};

OwningFixture BuildOwningFixture()
{
    OwningFixture out;
    const auto params = TinyParams();
    std::string why;
    auto manifest = rc::BuildRCStage3GemmExtractManifest(
        params, rc::RCStage3EpisodeStatementCommitment(
                    out.outer),
        Bindings(params), &why);
    BOOST_REQUIRE_MESSAGE(manifest.has_value(), why);
    out.manifest = *manifest;
    out.gemm.layers.resize(out.manifest.layers.size());
    out.extract.tiles.resize(
        out.manifest.total_extract_tiles);
    for (uint32_t ordinal = 0;
         ordinal < out.manifest.layers.size(); ++ordinal) {
        const auto& spec = out.manifest.layers[ordinal];
        auto& layer = out.gemm.layers[ordinal];
        layer.layer_ordinal = ordinal;
        layer.operand_a.assign(
            uint64_t{spec.m} * spec.k,
            static_cast<int8_t>(1 + ordinal % 11));
        layer.operand_b.assign(
            uint64_t{spec.k} * spec.n,
            static_cast<int8_t>(-1 -
                static_cast<int32_t>(ordinal % 11)));
        layer.gemm_y.assign(
            uint64_t{spec.m} * spec.n,
            static_cast<int64_t>(101 + ordinal));
        for (uint64_t tile = 0;
             tile < spec.extract_tile_count; ++tile) {
            auto& input =
                out.extract.tiles[
                    spec.extract_tile_begin + tile].input;
            for (uint32_t lane = 0;
                 lane < input.size(); ++lane) {
                input[lane] =
                    static_cast<int64_t>(
                        ordinal * 10000U +
                        tile * 32U + lane);
            }
        }
    }
    BOOST_REQUIRE_MESSAGE(
        rc::BindRCStage3EpisodeGemmAlgAuthorityRoots(
            out.manifest, out.gemm, out.extract, &why),
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
    BOOST_CHECK(audit.memory_roots_proof_owned);
    BOOST_CHECK(!audit.owning_producer_roots_bound);
    BOOST_CHECK_NE(
        audit.note.find("owning_producer_root"),
        std::string::npos);
    BOOST_CHECK(audit.exact_all_instance_aggregation);
    BOOST_CHECK(!audit.production_all_instance_aggregation);
    BOOST_CHECK(audit.proof_level_tamper_rejected);
    BOOST_CHECK(!audit.normalized_parent_accepts_sha_children);
    BOOST_CHECK(!audit.cross_hash_value_equality_proved);
    BOOST_CHECK(!audit.recursively_consumed);
    BOOST_CHECK_EQUAL(
        audit.residual_obligations,
        topo::ProductionResidualSourceRootProvenance |
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
    owning_gemm_values_regenerate_the_only_accepted_a_b_y_statement)
{
    const auto fixture = BuildOwningFixture();
    std::string why;
    owned::StatementV1 statement;
    BOOST_REQUIRE_MESSAGE(
        owned::BuildStatementFromOwningGemmProductV1(
            fixture.outer, fixture.manifest, fixture.gemm,
            fixture.extract, statement, &why),
        why);
    BOOST_CHECK(
        statement.episode_statement_commitment ==
        rc::RCStage3EpisodeStatementCommitment(
            fixture.outer));
    for (const auto& endpoint : statement.endpoints) {
        BOOST_CHECK_GT(endpoint.total_instance_count, 0U);
        BOOST_CHECK(!endpoint.canonical_value_roots.empty());
    }

    auto root_mutation = fixture.manifest;
    root_mutation.layers[0]
        .bindings.operand_b_root_alg = Root(0xd1);
    owned::StatementV1 rejected;
    BOOST_CHECK(
        !owned::BuildStatementFromOwningGemmProductV1(
            fixture.outer, root_mutation, fixture.gemm,
            fixture.extract, rejected, &why));

    BOOST_REQUIRE_GT(fixture.manifest.layers.size(), 1U);
    auto root_transplant = fixture.manifest;
    std::swap(
        root_transplant.layers[0]
            .bindings.operand_a_root_alg,
        root_transplant.layers[1]
            .bindings.operand_a_root_alg);
    BOOST_CHECK(
        !owned::BuildStatementFromOwningGemmProductV1(
            fixture.outer, root_transplant, fixture.gemm,
            fixture.extract, rejected, &why));

    auto producer_mutation = fixture.gemm;
    ++producer_mutation.layers[0].gemm_y[0];
    BOOST_CHECK(
        !owned::BuildStatementFromOwningGemmProductV1(
            fixture.outer, fixture.manifest,
            producer_mutation, fixture.extract,
            rejected, &why));

    auto extract_mutation = fixture.extract;
    ++extract_mutation.tiles[0].input[0];
    BOOST_CHECK(
        !owned::BuildStatementFromOwningGemmProductV1(
            fixture.outer, fixture.manifest, fixture.gemm,
            extract_mutation, rejected, &why));
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
