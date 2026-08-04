// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_relation_product.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_episode_relation_product_tests,
    BasicTestingSetup)

namespace {

uint256 Filled(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

rc::RCEpisodeParams SmallParams()
{
    rc::RCEpisodeParams p;
    p.rounds = 1;
    p.d_head = 32;
    p.n_q = 32;
    p.n_ctx = 32;
    p.L_lyr = 1;
    p.d_model = 32;
    p.d_ff = 32;
    p.b_seq = 32;
    p.T_leaf = 32;
    return p;
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof statement;
    statement.statement = rc::RCStage3StatementKind::Episode;
    auto& p = statement.public_inputs;
    p.height = 44;
    p.n_bits = 0x207fffff;
    p.episode_profile = 2;
    p.transcript_version = 1;
    p.header_commitment = Filled(0x11);
    p.params_commitment = Filled(0x22);
    p.target = Filled(0x7f);
    p.sigma = Filled(0x33);
    p.episode_digest = Filled(0x44);
    p.final_digest = Filled(0x55);
    return statement;
}

std::vector<gf::Fp3> EdgeValues(
    uint32_t first_column, uint64_t count)
{
    std::vector<gf::Fp3> values(count);
    for (uint64_t i = 0; i < count; ++i) {
        values[i] = gf::Fp3::FromFp(
            static_cast<uint64_t>(
                1 + first_column * 17 + (i % 251)));
    }
    return values;
}

std::vector<rc::RCStage3GemmExtractLayerBindings>
BindingsWithCanonicalDirectRoots(
    const rc::RCEpisodeParams& params,
    const uint256& statement_commitment)
{
    const auto layout = rc::RCGkrTraceLayout(params);
    std::vector<rc::RCStage3GemmExtractLayerBindings> out(
        layout.layers.size());
    uint32_t counter = 1;
    auto next_root = [&] {
        return Filled(static_cast<unsigned char>(
            1 + ((counter++) % 250)));
    };
    for (uint32_t ordinal = 0; ordinal < layout.layers.size();
         ++ordinal) {
        auto& binding = out[ordinal];
        binding.extract_prf = next_root();
        binding.operand_a_root = next_root();
        binding.operand_b_root = next_root();
        binding.gemm_y_root = next_root();
        binding.extract_input_root = next_root();
        binding.extract_output_root = next_root();
        binding.gemm_proof_root = next_root();
        binding.extract_recursive_root = next_root();
        binding.scale_schedule_root = next_root();
        binding.ctl_terminal_root = next_root();

        const auto& layer = layout.layers[ordinal];
        if (!layer.a.transpose) {
            const auto values =
                EdgeValues(
                    layer.a.first_column,
                    static_cast<uint64_t>(layer.m) * layer.k);
            std::string why;
            const auto root =
                rc::ComputeRCStage3EpisodeWiringVectorRootFromValues(
                    statement_commitment, layer.a.first_column,
                    layer.a.n_chunks, values, &why);
            BOOST_REQUIRE_MESSAGE(root.has_value(), why);
            binding.operand_a_root = *root;
        }
        if (!layer.b.transpose) {
            const auto values =
                EdgeValues(
                    layer.b.first_column,
                    static_cast<uint64_t>(layer.k) * layer.n);
            std::string why;
            const auto root =
                rc::ComputeRCStage3EpisodeWiringVectorRootFromValues(
                    statement_commitment, layer.b.first_column,
                    layer.b.n_chunks, values, &why);
            BOOST_REQUIRE_MESSAGE(root.has_value(), why);
            binding.operand_b_root = *root;
        }
    }
    return out;
}

rc::RCStage3GemmExtractManifest Manifest(
    const rc::RCStage3SuccinctProof& statement)
{
    const auto params = SmallParams();
    const uint256 statement_commitment =
        rc::RCStage3EpisodeStatementCommitment(statement);
    std::string why;
    const auto manifest = rc::BuildRCStage3GemmExtractManifest(
        params, statement_commitment,
        BindingsWithCanonicalDirectRoots(
            params, statement_commitment),
        &why);
    BOOST_REQUIRE_MESSAGE(manifest.has_value(), why);
    return *manifest;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    schedule_is_exact_lambda_projection_and_excludes_transpose)
{
    const auto statement = Statement();
    const auto manifest = Manifest(statement);
    const auto layout = rc::RCGkrTraceLayout(manifest.params);
    std::string why;
    const auto schedule =
        rc::BuildRCStage3EpisodeWiringCopySchedule(
            manifest, &why);
    BOOST_REQUIRE_MESSAGE(schedule.has_value(), why);

    uint32_t expected_index = 0;
    for (uint32_t ordinal = 0; ordinal < layout.layers.size();
         ++ordinal) {
        const auto& layer = layout.layers[ordinal];
        for (const auto slot : {
                 rc::RCStage3EpisodeWiringOperandSlot::A,
                 rc::RCStage3EpisodeWiringOperandSlot::B}) {
            const auto& ref =
                slot == rc::RCStage3EpisodeWiringOperandSlot::A
                ? layer.a : layer.b;
            if (ref.transpose) continue;
            BOOST_REQUIRE_LT(expected_index, schedule->size());
            const auto& entry = (*schedule)[expected_index];
            BOOST_CHECK_EQUAL(entry.schedule_index, expected_index);
            BOOST_CHECK_EQUAL(entry.layer_ordinal, ordinal);
            BOOST_CHECK(entry.slot == slot);
            BOOST_CHECK_EQUAL(entry.first_column, ref.first_column);
            BOOST_CHECK_EQUAL(entry.n_chunks, ref.n_chunks);
            const uint64_t expected_count =
                slot == rc::RCStage3EpisodeWiringOperandSlot::A
                ? static_cast<uint64_t>(layer.m) * layer.k
                : static_cast<uint64_t>(layer.k) * layer.n;
            BOOST_CHECK_EQUAL(entry.value_count, expected_count);
            BOOST_CHECK(!entry.registered_vector_root.IsNull());
            ++expected_index;
        }
    }
    BOOST_CHECK_EQUAL(expected_index, schedule->size());

    auto changed = manifest;
    changed.layers[0].a.first_column += 1;
    BOOST_CHECK(
        !rc::BuildRCStage3EpisodeWiringCopySchedule(
             changed, &why).has_value());
    BOOST_CHECK(
        why.find("layout_mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    edge_product_executes_relation_and_both_exact_memory_sides)
{
    const auto statement = Statement();
    const auto manifest = Manifest(statement);
    std::string why;
    const auto schedule =
        rc::BuildRCStage3EpisodeWiringCopySchedule(
            manifest, &why);
    BOOST_REQUIRE_MESSAGE(schedule.has_value(), why);
    const auto& expected = schedule->front();
    const auto values =
        EdgeValues(expected.first_column, expected.value_count);

    rc::RCStage3EpisodeWiringCopyEdgeProduct product;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeWiringCopyEdgeProduct(
            statement, manifest, expected, values, values,
            product, &why), why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeWiringCopyEdgeProduct(
            statement, manifest, expected, product, &why), why);
    BOOST_CHECK_EQUAL(product.relation_shards.size(), 1U);
    BOOST_CHECK_EQUAL(product.source_memory.shards.size(), 1U);
    BOOST_CHECK_EQUAL(
        product.destination_memory.shards.size(), 1U);
    BOOST_CHECK(
        product.relation_shards[0].pin.column_roots[0].root ==
        product.source_memory.shards[0]
            .manifest.canonical_value_root);
    BOOST_CHECK(
        product.relation_shards[0].pin.column_roots[1].root ==
        product.destination_memory.shards[0]
            .manifest.canonical_value_root);

    auto missing = product;
    missing.relation_shards.clear();
    missing.product_commitment =
        rc::ComputeRCStage3EpisodeWiringCopyEdgeProductCommitment(
            missing);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeWiringCopyEdgeProduct(
            statement, manifest, expected, missing, &why));
    BOOST_CHECK(
        why.find("shard_count") != std::string::npos);

    auto detached_memory = product;
    detached_memory.source_memory.shards[0]
        .manifest.canonical_value_root = Filled(0xee);
    detached_memory.product_commitment =
        rc::ComputeRCStage3EpisodeWiringCopyEdgeProductCommitment(
            detached_memory);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeWiringCopyEdgeProduct(
            statement, manifest, expected, detached_memory, &why));

    auto relabelled = product;
    relabelled.schedule.slot =
        rc::RCStage3EpisodeWiringOperandSlot::B;
    relabelled.product_commitment =
        rc::ComputeRCStage3EpisodeWiringCopyEdgeProductCommitment(
            relabelled);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeWiringCopyEdgeProduct(
            statement, manifest, expected, relabelled, &why));
    BOOST_CHECK(
        why.find("public_shape") != std::string::npos);

    auto root_substitution = product;
    root_substitution.relation_shards[0]
        .pin.column_roots[0].root = Filled(0xf1);
    root_substitution.product_commitment =
        rc::ComputeRCStage3EpisodeWiringCopyEdgeProductCommitment(
            root_substitution);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeWiringCopyEdgeProduct(
            statement, manifest, expected, root_substitution,
            &why));
}

BOOST_AUTO_TEST_CASE(
    closure_rejects_omission_before_proof_execution)
{
    const auto statement = Statement();
    const auto manifest = Manifest(statement);
    rc::RCStage3EpisodeWiringCopyClosure closure;
    closure.statement_commitment =
        rc::RCStage3EpisodeStatementCommitment(statement);
    closure.manifest_commitment =
        rc::ComputeRCStage3GemmExtractManifestCommitment(manifest);
    std::string why;
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeWiringCopyClosure(
            statement, manifest, closure, &why));
    BOOST_CHECK(
        why.find("edge_count") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    endpoint_status_separates_local_closure_from_producer_provenance)
{
    const auto status =
        rc::CurrentRCStage3EpisodeRelationProductEndpointStatus();
    BOOST_REQUIRE_EQUAL(status.size(), 6U);
    uint32_t local = 0;
    uint32_t strict = 0;
    for (const auto& entry : status) {
        BOOST_CHECK(entry.immutable_full_schedule);
        BOOST_CHECK(entry.relation_proof_executed);
        BOOST_CHECK(!entry.recursively_consumed);
        if (entry.all_instances_closed) {
            ++local;
            BOOST_CHECK(
                entry.endpoint ==
                rc::RCStage3RelationEndpoint::EpisodeWiringCopy);
            BOOST_CHECK(entry.exact_memory_root_alias);
        } else {
            BOOST_CHECK(!entry.exact_memory_root_alias);
            BOOST_CHECK(!entry.residual.empty());
        }
        strict += entry.all_instances_closed &&
                  entry.producer_root_authenticated;
    }
    BOOST_CHECK_EQUAL(local, 1U);
    BOOST_CHECK_EQUAL(strict, 0U);
    BOOST_CHECK(
        !rc::kRCStage3EpisodeWiringCopyStrictSemanticEndpointExecutable);
    BOOST_CHECK(
        !rc::kRCStage3EpisodeRelationProductRecursivelyConsumed);
    BOOST_CHECK(
        !rc::kRCStage3EpisodeRelationProductAuthorityReady);
    BOOST_CHECK(!rc::kRCStage3SuccinctAuthorityReady);
}

BOOST_AUTO_TEST_SUITE_END()
