// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_episode_builder_trace.h>
#include <matmul/matmul_v4_rc_stage3_provenance_graph.h>

namespace {

namespace rc = matmul::v4::rc;
namespace ha = rc::stage3_hash_air;

uint256 H(unsigned char value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{Span<const unsigned char>{
        bytes.data(), bytes.size()}};
}

void AppendLe32(std::vector<uint8_t>& out, uint32_t value)
{
    for (uint32_t shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<uint8_t>(value >> shift));
    }
}

bool Fixture(
    rc::RCStage3SuccinctProof& statement,
    rc::RCEpisodeParams& params,
    rc::RCStage3EpisodeBuilderParamsProduct& params_product,
    rc::RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    rc::RCStage3EpisodeBuilderOperandXofProduct& operand_xof,
    std::string* why)
{
    params = rc::MakeToyRCEpisodeParams();
    std::vector<uint256> roots{H(0x61)};
    ha::EpisodeDigestManifest digest;
    if (!ha::BuildEpisodeDigestManifest(
            roots.size(), roots, digest, why)) {
        return false;
    }
    statement = {};
    statement.statement = rc::RCStage3StatementKind::Episode;
    statement.public_inputs.height = 17;
    statement.public_inputs.episode_profile = 2;
    statement.public_inputs.transcript_version = rc::ENC_RC_V4;
    statement.public_inputs.header_commitment = H(0x11);
    statement.public_inputs.params_commitment = H(0x22);
    statement.public_inputs.sigma = H(0x33);
    statement.public_inputs.episode_digest =
        digest.direct.digest;
    const uint256 statement_commitment =
        rc::RCStage3EpisodeStatementCommitment(statement);
    if (!rc::ProveRCStage3EpisodeBuilderParamsProduct(
            statement_commitment, params, params_product, why)) {
        return false;
    }

    seed_chain = {};
    seed_chain.statement_commitment = statement_commitment;
    seed_chain.header_commitment =
        statement.public_inputs.header_commitment;
    seed_chain.params_commitment =
        statement.public_inputs.params_commitment;
    seed_chain.sigma = statement.public_inputs.sigma;
    seed_chain.expected_rounds = 1;
    seed_chain.round_root_manifest = digest;
    seed_chain.params_product = params_product;
    seed_chain.steps.resize(1);
    seed_chain.steps[0].round_index = 0;
    seed_chain.steps[0].source = seed_chain.sigma;
    std::vector<uint8_t> preimage(
        reinterpret_cast<const uint8_t*>(rc::kRCRoundTag),
        reinterpret_cast<const uint8_t*>(rc::kRCRoundTag) +
            sizeof(rc::kRCRoundTag) - 1);
    preimage.insert(
        preimage.end(), seed_chain.sigma.begin(),
        seed_chain.sigma.end());
    AppendLe32(preimage, 0);
    if (!ha::BuildShaManifest(
            preimage, ha::ShaMode::Single,
            seed_chain.steps[0].sha, why)) {
        return false;
    }
    seed_chain.steps[0].hash_proof.endpoint =
        rc::RCStage3RelationEndpoint::EpisodeBuilderSeedChain;
    seed_chain.steps[0].hash_proof.statement_commitment =
        statement_commitment;
    seed_chain.steps[0].hash_proof.manifest_commitment =
        seed_chain.steps[0].sha.commitment;
    seed_chain.round_roots_pin.pin_commitment = H(0x72);
    seed_chain.seed_memory_manifest.manifest_commitment = H(0x73);
    seed_chain.product_commitment =
        rc::ComputeRCStage3EpisodeBuilderSeedChainProductCommitment(
            seed_chain);
    if (seed_chain.product_commitment.IsNull()) return false;
    return rc::BuildRCStage3EpisodeBuilderOperandXofProduct(
        statement, params, seed_chain, operand_xof, why);
}

std::vector<rc::RCStage3GemmExtractLayerBindings> Bindings(
    const rc::RCGkrLayout& layout,
    const rc::RCStage3EpisodeBuilderTraceProduct& trace)
{
    std::vector<rc::RCStage3GemmExtractLayerBindings> out(
        layout.layers.size());
    uint32_t byte = 1;
    auto next = [&] {
        return H(static_cast<unsigned char>(1 + (byte++ % 250)));
    };
    const auto root_for =
        [&](uint32_t first_column) -> std::optional<uint256> {
            for (const auto& column : trace.trace_columns) {
                if (column.first_column == first_column) {
                    return column.wiring_vector_root;
                }
            }
            return std::nullopt;
        };
    for (uint32_t i = 0; i < layout.layers.size(); ++i) {
        auto& binding = out[i];
        binding.extract_prf = next();
        binding.operand_a_root =
            root_for(layout.layers[i].a.first_column)
                .value_or(next());
        binding.operand_b_root =
            root_for(layout.layers[i].b.first_column)
                .value_or(next());
        binding.gemm_y_root = next();
        binding.extract_input_root = next();
        binding.extract_output_root = next();
        binding.gemm_proof_root = next();
        binding.extract_recursive_root = next();
        binding.scale_schedule_root = next();
        binding.ctl_terminal_root = next();
    }
    return out;
}

std::vector<int8_t> ExpansionValues(
    const rc::RCStage3EpisodeBuilderTraceExpansion& expansion,
    const rc::RCStage3EpisodeBuilderOperandXofProduct& operand_xof)
{
    std::vector<int8_t> out;
    out.reserve(
        static_cast<uint64_t>(expansion.rows) * expansion.cols);
    for (uint32_t index : expansion.operand_xof_indices) {
        BOOST_REQUIRE_LT(index, operand_xof.instances.size());
        const auto& source = operand_xof.instances[index];
        const uint64_t cells =
            static_cast<uint64_t>(source.rows) * source.cols;
        BOOST_REQUIRE_EQUAL(source.mantissa.output.size(), cells);
        BOOST_REQUIRE_EQUAL(
            source.scale.output.size(),
            static_cast<uint64_t>(source.rows) *
                (source.cols / rc::kRCMxBlockLen));
        for (uint64_t cell = 0; cell < cells; ++cell) {
            const uint8_t encoded = source.mantissa.output[cell];
            const int64_t mantissa =
                encoded < 128
                ? encoded : static_cast<int64_t>(encoded) - 256;
            const uint8_t scale =
                source.scale.output[cell / rc::kRCMxBlockLen];
            const int64_t value =
                mantissa * (int64_t{1} << scale);
            BOOST_REQUIRE_GE(value, -128);
            BOOST_REQUIRE_LE(value, 127);
            out.push_back(static_cast<int8_t>(value));
        }
    }
    BOOST_REQUIRE_EQUAL(
        out.size(),
        static_cast<uint64_t>(expansion.rows) * expansion.cols);
    return out;
}

std::optional<std::vector<int8_t>> TraceValues(
    uint32_t first_column,
    const rc::RCStage3EpisodeBuilderTraceProduct& trace,
    const rc::RCStage3EpisodeBuilderOperandXofProduct& operand_xof)
{
    const auto found = std::find_if(
        trace.trace_columns.begin(), trace.trace_columns.end(),
        [first_column](const auto& column) {
            return column.first_column == first_column;
        });
    if (found == trace.trace_columns.end()) return std::nullopt;
    BOOST_REQUIRE_LT(found->expansion_index, trace.expansions.size());
    return ExpansionValues(
        trace.expansions[found->expansion_index], operand_xof);
}

std::vector<rc::gkr_field::Fp3> ToField(
    const std::vector<int8_t>& values)
{
    std::vector<rc::gkr_field::Fp3> out;
    out.reserve(values.size());
    for (int8_t value : values) {
        out.push_back(rc::gkr_field::Fp3::FromFp(
            rc::gkr_field::FromSigned(value)));
    }
    return out;
}

uint256 VectorRoot(
    const uint256& statement_commitment,
    const rc::RCGkrOperandRef& ref,
    const std::vector<int8_t>& values)
{
    std::string why;
    const auto root =
        rc::ComputeRCStage3EpisodeWiringVectorRootFromValues(
            statement_commitment, ref.first_column,
            ref.n_chunks, ToField(values), &why);
    BOOST_REQUIRE_MESSAGE(root.has_value(), why);
    return *root;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_episode_builder_trace_tests)

BOOST_AUTO_TEST_CASE(
    exact_trace_composition_and_manifest_binding_reject_attacks)
{
    rc::RCStage3SuccinctProof statement;
    rc::RCEpisodeParams params;
    rc::RCStage3EpisodeBuilderParamsProduct params_product;
    rc::RCStage3EpisodeBuilderSeedChainProduct seed_chain;
    rc::RCStage3EpisodeBuilderOperandXofProduct operand_xof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        Fixture(
            statement, params, params_product, seed_chain,
            operand_xof, &why),
        why);

    rc::RCStage3EpisodeBuilderTraceProduct product;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeBuilderTraceProduct(
            statement, params, params_product, seed_chain,
            operand_xof, product, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3EpisodeBuilderTraceSchedule(
            statement, params, params_product, seed_chain,
            operand_xof, product, &why),
        why);
    std::vector<rc::RCStage3EpisodeBuilderTraceLeafOpening>
        leaf_openings;
    BOOST_REQUIRE_MESSAGE(
        rc::MaterializeRCStage3EpisodeBuilderTraceLeafOpenings(
            statement, params, params_product, seed_chain,
            operand_xof, product, leaf_openings, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        leaf_openings.size(), product.trace_columns.size());
    for (uint32_t i = 0; i < leaf_openings.size(); ++i) {
        const auto expected = TraceValues(
            product.trace_columns[i].first_column,
            product, operand_xof);
        BOOST_REQUIRE(expected.has_value());
        BOOST_CHECK(leaf_openings[i].values == *expected);
        BOOST_CHECK_EQUAL(
            leaf_openings[i].first_column,
            product.trace_columns[i].first_column);
    }
    BOOST_CHECK_EQUAL(product.expansions.size(), 8U);
    BOOST_CHECK_EQUAL(product.trace_columns.size(), 8U);
    BOOST_CHECK_EQUAL(product.root_memory.total_instance_count, 8U);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeBuilderTraceLocalProduct(
            statement, params, params_product, seed_chain,
            operand_xof, product, &why),
        why);
    // The fixture deliberately has no endpoint-2/3 proof bundles.
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeBuilderTraceProduct(
            statement, params, params_product, seed_chain,
            operand_xof, product, &why));

    const auto layout = rc::RCGkrTraceLayout(params);
    auto manifest = rc::BuildRCStage3GemmExtractManifest(
        params, product.statement_commitment,
        Bindings(layout, product), &why);
    BOOST_REQUIRE_MESSAGE(manifest.has_value(), why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeBuilderTraceManifestBinding(
            statement, params, product, *manifest, &why),
        why);

    auto omitted = product;
    omitted.expansions.pop_back();
    omitted.product_commitment =
        rc::ComputeRCStage3EpisodeBuilderTraceProductCommitment(
            omitted);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeBuilderTraceSchedule(
            statement, params, params_product, seed_chain,
            operand_xof, omitted, &why));

    auto reordered = product;
    std::swap(reordered.expansions[0], reordered.expansions[1]);
    reordered.product_commitment =
        rc::ComputeRCStage3EpisodeBuilderTraceProductCommitment(
            reordered);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeBuilderTraceSchedule(
            statement, params, params_product, seed_chain,
            operand_xof, reordered, &why));

    auto source_substitution = product;
    source_substitution.expansions[0].source_link_root = H(0xa1);
    source_substitution.product_commitment =
        rc::ComputeRCStage3EpisodeBuilderTraceProductCommitment(
            source_substitution);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeBuilderTraceSchedule(
            statement, params, params_product, seed_chain,
            operand_xof, source_substitution, &why));

    auto output_substitution = product;
    output_substitution.expansions[0].shards[0].output_root =
        H(0xa2);
    output_substitution.product_commitment =
        rc::ComputeRCStage3EpisodeBuilderTraceProductCommitment(
            output_substitution);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeBuilderTraceSchedule(
            statement, params, params_product, seed_chain,
            operand_xof, output_substitution, &why));

    auto proof_substitution = product;
    proof_substitution.expansions[0].shards[0]
        .proof.batch.columns[0].root = H(0xa5);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeBuilderTraceLocalProduct(
            statement, params, params_product, seed_chain,
            operand_xof, proof_substitution, &why));

    auto root_substitution = product;
    root_substitution.builder_trace_root = H(0xa3);
    root_substitution.product_commitment =
        rc::ComputeRCStage3EpisodeBuilderTraceProductCommitment(
            root_substitution);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeBuilderTraceSchedule(
            statement, params, params_product, seed_chain,
            operand_xof, root_substitution, &why));

    auto manifest_substitution = *manifest;
    manifest_substitution.layers[0].bindings.operand_a_root =
        H(0xa4);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeBuilderTraceManifestBinding(
            statement, params, product,
            manifest_substitution, &why));
}

BOOST_AUTO_TEST_CASE(
    bounded_episode_producer_links_reject_cross_product_substitution)
{
    rc::RCStage3SuccinctProof statement;
    rc::RCEpisodeParams params;
    rc::RCStage3EpisodeBuilderParamsProduct params_product;
    rc::RCStage3EpisodeBuilderSeedChainProduct seed_chain;
    rc::RCStage3EpisodeBuilderOperandXofProduct operand_xof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        Fixture(
            statement, params, params_product, seed_chain,
            operand_xof, &why),
        why);
    rc::RCStage3EpisodeBuilderTraceProduct builder;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeBuilderTraceProduct(
            statement, params, params_product, seed_chain,
            operand_xof, builder, &why),
        why);

    const auto layout = rc::RCGkrTraceLayout(params);
    std::vector<rc::RCStage3GemmExtractLayerBindings> bindings(
        layout.layers.size());
    const uint256 statement_commitment =
        rc::RCStage3EpisodeStatementCommitment(statement);
    uint8_t marker = 1;
    for (uint32_t ordinal = 0;
         ordinal < layout.layers.size(); ++ordinal) {
        const auto& spec = layout.layers[ordinal];
        auto& binding = bindings[ordinal];
        const auto a = TraceValues(
            spec.a.first_column, builder, operand_xof)
            .value_or(std::vector<int8_t>(
                static_cast<uint64_t>(spec.m) * spec.k, 0));
        const auto b = TraceValues(
            spec.b.first_column, builder, operand_xof)
            .value_or(std::vector<int8_t>(
                static_cast<uint64_t>(spec.k) * spec.n, 0));
        binding.operand_a_root =
            VectorRoot(statement_commitment, spec.a, a);
        binding.operand_b_root =
            VectorRoot(statement_commitment, spec.b, b);
        binding.gemm_y_root = VectorRoot(
            statement_commitment,
            {spec.y_first_column, spec.y_chunks, false},
            std::vector<int8_t>(
                static_cast<uint64_t>(spec.m) * spec.n, 0));
        binding.extract_prf = H(marker++);
        binding.extract_input_root = H(marker++);
        binding.extract_output_root = H(marker++);
        binding.gemm_proof_root = H(marker++);
        binding.extract_recursive_root = H(marker++);
        binding.scale_schedule_root = H(marker++);
        binding.ctl_terminal_root = H(marker++);
    }
    const auto built_manifest =
        rc::BuildRCStage3GemmExtractManifest(
            params, statement_commitment, bindings, &why);
    BOOST_REQUIRE_MESSAGE(built_manifest.has_value(), why);
    const auto& manifest = *built_manifest;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3EpisodeBuilderTraceManifestBinding(
            statement, params, builder, manifest, &why),
        why);

    rc::RCStage3EpisodeGemmProduct gemm;
    gemm.statement_commitment = statement_commitment;
    gemm.manifest_commitment =
        rc::ComputeRCStage3GemmExtractManifestCommitment(
            manifest);
    gemm.layers.resize(manifest.layers.size());
    rc::RCStage3EpisodeExtractProduct extract;
    extract.statement_commitment = statement_commitment;
    extract.manifest_commitment = gemm.manifest_commitment;
    extract.expected_tiles = manifest.total_extract_tiles;
    extract.tiles.reserve(extract.expected_tiles);

    for (uint32_t ordinal = 0;
         ordinal < manifest.layers.size(); ++ordinal) {
        const auto& spec = manifest.layers[ordinal];
        auto& layer = gemm.layers[ordinal];
        layer.layer_ordinal = ordinal;
        layer.operand_a = TraceValues(
            spec.a.first_column, builder, operand_xof)
            .value_or(std::vector<int8_t>(
                static_cast<uint64_t>(spec.m) * spec.k, 0));
        layer.operand_b = TraceValues(
            spec.b.first_column, builder, operand_xof)
            .value_or(std::vector<int8_t>(
                static_cast<uint64_t>(spec.k) * spec.n, 0));
        layer.gemm_y.assign(spec.gemm_cell_count, 0);
        if (spec.residual_first_column >= 0) {
            layer.residual = TraceValues(
                static_cast<uint32_t>(
                    spec.residual_first_column),
                builder, operand_xof)
                .value_or(std::vector<int8_t>(
                    spec.gemm_cell_count, 0));
        }
        for (uint64_t local = 0;
             local < spec.extract_tile_count; ++local) {
            rc::RCStage3EpisodeExtractTileProduct tile;
            tile.global_tile = extract.tiles.size();
            tile.layer_ordinal = ordinal;
            tile.layer_tile_index = local;
            for (uint32_t lane = 0;
                 lane < rc::kRCMxBlockLen; ++lane) {
                const uint64_t index =
                    local * rc::kRCMxBlockLen + lane;
                tile.input[lane] =
                    layer.residual.empty()
                    ? 0 : layer.residual[index];
            }
            tile.sampler_pin.logical_rows = rc::kRCMxBlockLen;
            tile.sampler_pin.n_rows = rc::kRCMxBlockLen;
            tile.sampler_pin.n_coeffs = rc::kRCMxBlockLen;
            tile.sampler_pin.column_roots.resize(
                rc::air_quotient::kRcSamplerNumCols);
            for (uint32_t column = 0;
                 column < rc::air_quotient::kRcSamplerNumCols;
                 ++column) {
                tile.sampler_pin.column_roots[column] = {
                    column, H(static_cast<uint8_t>(
                        1 + ((column + ordinal) % 250)))};
            }
            tile.sampler_pin.column_roots[
                rc::air_quotient::kColOut].root =
                rc::air_quotient::AirCommittedValuesRoot<
                    rc::gkr_field::Fp3>(
                    std::vector<rc::gkr_field::Fp3>(
                        rc::kRCMxBlockLen,
                        rc::gkr_field::Fp3::Zero()),
                    rc::kRCMxBlockLen);
            extract.tiles.push_back(std::move(tile));
        }
    }
    gemm.collection_commitment = H(0xc1);
    extract.collection_commitment = H(0xc2);

    const auto copy_schedule =
        rc::BuildRCStage3EpisodeWiringCopySchedule(
            manifest, &why);
    BOOST_REQUIRE_MESSAGE(copy_schedule.has_value(), why);
    gemm.wiring.statement_commitment = statement_commitment;
    gemm.wiring.manifest_commitment = gemm.manifest_commitment;
    for (const auto& edge : *copy_schedule) {
        const auto& layer =
            gemm.layers[edge.layer_ordinal];
        const auto& values =
            edge.slot ==
                rc::RCStage3EpisodeWiringOperandSlot::A
            ? layer.operand_a : layer.operand_b;
        rc::RCStage3EpisodeWiringCopyEdgeProduct product;
        BOOST_REQUIRE_MESSAGE(
            rc::ProveRCStage3EpisodeWiringCopyEdgeProduct(
                statement, manifest, edge, ToField(values),
                ToField(values), product, &why),
            why);
        gemm.wiring.edges.push_back(std::move(product));
    }
    gemm.wiring.closure_commitment =
        rc::ComputeRCStage3EpisodeWiringCopyClosureCommitment(
            gemm.wiring);
    BOOST_REQUIRE(!gemm.wiring.closure_commitment.IsNull());

    rc::RCStage3EpisodeWiringProduct wiring;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeWiringProduct(
            statement, manifest, gemm, extract, wiring, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3BoundedEpisodeProducerLinks(
            statement, params, builder, manifest, gemm,
            extract, wiring, &why),
        why);

    auto builder_attack = builder;
    builder_attack.trace_columns[0].wiring_vector_root =
        H(0xd1);
    BOOST_CHECK(
        !rc::VerifyRCStage3BoundedEpisodeProducerLinks(
            statement, params, builder_attack, manifest, gemm,
            extract, wiring, &why));

    auto gemm_attack = gemm;
    gemm_attack.layers[0].operand_a[0] ^= 1;
    BOOST_CHECK(
        !rc::VerifyRCStage3BoundedEpisodeProducerLinks(
            statement, params, builder, manifest, gemm_attack,
            extract, wiring, &why));

    auto extract_attack = extract;
    extract_attack.tiles[0].input[0] += 1;
    BOOST_CHECK(
        !rc::VerifyRCStage3BoundedEpisodeProducerLinks(
            statement, params, builder, manifest, gemm,
            extract_attack, wiring, &why));

    auto copy_attack = gemm;
    copy_attack.wiring.edges[0]
        .source_memory.bundle_commitment = H(0xd2);
    BOOST_CHECK(
        !rc::VerifyRCStage3BoundedEpisodeProducerLinks(
            statement, params, builder, manifest, copy_attack,
            extract, wiring, &why));

    auto wiring_attack = wiring;
    wiring_attack.gemm_product_commitment = H(0xd3);
    wiring_attack.product_commitment =
        rc::ComputeRCStage3EpisodeWiringProductCommitment(
            wiring_attack);
    BOOST_CHECK(
        !rc::VerifyRCStage3BoundedEpisodeProducerLinks(
            statement, params, builder, manifest, gemm,
            extract, wiring_attack, &why));
}

BOOST_AUTO_TEST_CASE(
    audit_separates_bounded_transitive_streaming_and_recursion)
{
    const auto open =
        rc::CurrentRCStage3EpisodeBuilderTraceAudit(
            true, true, false);
    BOOST_CHECK(open.verifier_derived_layout_schedule);
    BOOST_CHECK(open.exact_endpoint_1_3_composition);
    BOOST_CHECK(open.all_dequant_children_executable);
    BOOST_CHECK(open.every_generated_source_linked);
    BOOST_CHECK(open.gemm_wiring_manifest_binding_executable);
    BOOST_CHECK(open.canonical_trace_root_memory_executable);
    BOOST_CHECK(open.bounded_local_relation_complete);
    BOOST_CHECK(!open.producer_provenance_complete);
    BOOST_CHECK(!open.semantic_complete);

    const auto closed =
        rc::CurrentRCStage3EpisodeBuilderTraceAudit(
            true, true, true);
    BOOST_CHECK(closed.producer_provenance_complete);
    BOOST_CHECK(closed.semantic_complete);
    BOOST_CHECK(!closed.production_streaming_complete);
    BOOST_CHECK(!closed.recursively_consumed);
    BOOST_CHECK(!closed.remaining.empty());
}

BOOST_AUTO_TEST_SUITE_END()
