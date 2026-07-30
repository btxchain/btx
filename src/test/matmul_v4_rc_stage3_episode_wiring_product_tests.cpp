// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_episode_wiring_product.h>

#include <algorithm>
#include <array>

namespace {

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace gf = rc::gkr_field;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{
        Span<const unsigned char>{bytes.data(), bytes.size()}};
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Episode;
    out.public_inputs.height = 183;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.episode_profile = 2;
    out.public_inputs.transcript_version = rc::ENC_RC_V4;
    out.public_inputs.header_commitment = H(0x11);
    out.public_inputs.params_commitment = H(0x22);
    out.public_inputs.sigma = H(0x33);
    out.public_inputs.target = H(0xff);
    out.public_inputs.episode_digest = H(0x44);
    out.public_inputs.final_digest = H(0x44);
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
PlaceholderBindings(const rc::RCEpisodeParams& params)
{
    const auto layout = rc::RCGkrTraceLayout(params);
    std::vector<rc::RCStage3GemmExtractLayerBindings> out(
        layout.layers.size());
    for (uint32_t i = 0; i < out.size(); ++i) {
        auto& binding = out[i];
        binding.extract_prf = H(0x10 + i);
        binding.operand_a_root = H(0x20 + i);
        binding.operand_b_root = H(0x30 + i);
        binding.gemm_y_root = H(0x40 + i);
        binding.extract_input_root = H(0x50 + i);
        binding.extract_output_root = H(0x60 + i);
        binding.gemm_proof_root = H(0x70 + i);
        binding.extract_recursive_root = H(0x80 + i);
        binding.scale_schedule_root = H(0x90 + i);
        binding.ctl_terminal_root = H(0xa0 + i);
    }
    return out;
}

std::vector<gf::Fp3> Zeros(uint64_t count)
{
    return std::vector<gf::Fp3>(count, gf::Fp3::Zero());
}

uint256 VectorRoot(
    const uint256& statement_commitment,
    uint32_t first_column,
    uint32_t n_chunks,
    uint64_t count)
{
    std::string why;
    const auto root =
        rc::ComputeRCStage3EpisodeWiringVectorRootFromValues(
            statement_commitment, first_column,
            n_chunks, Zeros(count), &why);
    BOOST_REQUIRE_MESSAGE(root.has_value(), why);
    return *root;
}

struct Fixture {
    rc::RCStage3SuccinctProof statement{Statement()};
    rc::RCStage3GemmExtractManifest manifest;
    rc::RCStage3EpisodeGemmProduct gemm;
    rc::RCStage3EpisodeExtractProduct extract;
    rc::RCStage3EpisodeWiringProduct wiring;
};

bool BuildFixture(Fixture& fixture, std::string* why)
{
    const auto params = TinyParams();
    const uint256 statement_commitment =
        rc::RCStage3EpisodeStatementCommitment(
            fixture.statement);
    const auto built = rc::BuildRCStage3GemmExtractManifest(
        params, statement_commitment,
        PlaceholderBindings(params), why);
    if (!built.has_value()) return false;
    fixture.manifest = *built;

    fixture.gemm.statement_commitment = statement_commitment;
    fixture.gemm.layers.resize(fixture.manifest.layers.size());
    for (uint32_t i = 0;
         i < fixture.manifest.layers.size(); ++i) {
        auto& spec = fixture.manifest.layers[i];
        auto& layer = fixture.gemm.layers[i];
        layer.layer_ordinal = i;
        layer.operand_a.assign(
            static_cast<uint64_t>(spec.m) * spec.k, 0);
        layer.operand_b.assign(
            static_cast<uint64_t>(spec.k) * spec.n, 0);
        layer.gemm_y.assign(spec.gemm_cell_count, 0);
        if (spec.residual_first_column >= 0) {
            layer.residual.assign(spec.gemm_cell_count, 0);
        }
        spec.bindings.operand_a_root = VectorRoot(
            statement_commitment,
            spec.a.first_column, spec.a.n_chunks,
            layer.operand_a.size());
        spec.bindings.operand_b_root = VectorRoot(
            statement_commitment,
            spec.b.first_column, spec.b.n_chunks,
            layer.operand_b.size());
        spec.bindings.gemm_y_root = VectorRoot(
            statement_commitment,
            spec.y_first_column, spec.y_chunks,
            layer.gemm_y.size());
    }

    fixture.gemm.manifest_commitment =
        rc::ComputeRCStage3GemmExtractManifestCommitment(
            fixture.manifest);
    fixture.gemm.collection_commitment = H(0xc1);

    fixture.extract.statement_commitment = statement_commitment;
    fixture.extract.manifest_commitment =
        fixture.gemm.manifest_commitment;
    fixture.extract.expected_tiles =
        fixture.manifest.total_extract_tiles;
    fixture.extract.tiles.reserve(
        fixture.extract.expected_tiles);
    const std::vector<gf::Fp3> zero_output(
        rc::kRCMxBlockLen, gf::Fp3::Zero());
    const uint256 zero_output_root =
        aq::AirCommittedValuesRoot<gf::Fp3>(
            zero_output, rc::kRCMxBlockLen);
    for (uint32_t layer_ordinal = 0;
         layer_ordinal < fixture.manifest.layers.size();
         ++layer_ordinal) {
        const auto& spec =
            fixture.manifest.layers[layer_ordinal];
        for (uint64_t local = 0;
             local < spec.extract_tile_count; ++local) {
            rc::RCStage3EpisodeExtractTileProduct tile;
            tile.global_tile = fixture.extract.tiles.size();
            tile.layer_ordinal = layer_ordinal;
            tile.layer_tile_index = local;
            tile.sampler_pin.logical_rows = rc::kRCMxBlockLen;
            tile.sampler_pin.n_rows = rc::kRCMxBlockLen;
            tile.sampler_pin.n_coeffs = rc::kRCMxBlockLen;
            tile.sampler_pin.column_roots.resize(
                aq::kRcSamplerNumCols);
            for (uint32_t column = 0;
                 column < aq::kRcSamplerNumCols; ++column) {
                tile.sampler_pin.column_roots[column] = {
                    column, H(static_cast<uint8_t>(
                        1 + ((column + layer_ordinal) % 250)))};
            }
            tile.sampler_pin.column_roots[
                aq::kColOut].root = zero_output_root;
            fixture.extract.tiles.push_back(std::move(tile));
        }
    }
    fixture.extract.collection_commitment = H(0xc2);

    return rc::BuildRCStage3EpisodeWiringProduct(
        fixture.statement, fixture.manifest,
        fixture.gemm, fixture.extract,
        fixture.wiring, why);
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_episode_wiring_product_tests)

BOOST_AUTO_TEST_CASE(
    exact_lambda_schedule_executes_endpoints_16_through_18)
{
    Fixture fixture;
    std::string why;
    BOOST_REQUIRE_MESSAGE(BuildFixture(fixture, &why), why);

    const auto transpose =
        rc::BuildRCStage3EpisodeWiringTransposeSchedule(
            fixture.manifest);
    const auto residual =
        rc::BuildRCStage3EpisodeWiringResidualSchedule(
            fixture.manifest);
    const auto order =
        rc::BuildRCStage3EpisodeWiringRoundOrderSchedule(
            fixture.manifest);
    BOOST_REQUIRE(!transpose.empty());
    BOOST_REQUIRE(!residual.empty());
    BOOST_REQUIRE(!order.empty());
    BOOST_CHECK_EQUAL(
        fixture.wiring.transpose_edges.size(),
        transpose.size());
    BOOST_CHECK_EQUAL(
        fixture.wiring.residual_edges.size(),
        residual.size());
    BOOST_CHECK_EQUAL(
        fixture.wiring.round_order_edges.size(),
        order.size());
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3EpisodeWiringProductSchedule(
            fixture.statement, fixture.manifest,
            fixture.gemm, fixture.extract,
            fixture.wiring, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeWiringLocalProduct(
            fixture.statement, fixture.manifest,
            fixture.gemm, fixture.extract,
            fixture.wiring, &why),
        why);
}

BOOST_AUTO_TEST_CASE(
    omission_reorder_transcript_and_root_substitution_reject)
{
    Fixture fixture;
    std::string why;
    BOOST_REQUIRE_MESSAGE(BuildFixture(fixture, &why), why);

    auto omitted = fixture.wiring;
    omitted.round_order_edges.pop_back();
    omitted.product_commitment =
        rc::ComputeRCStage3EpisodeWiringProductCommitment(
            omitted);
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeWiringProductSchedule(
        fixture.statement, fixture.manifest,
        fixture.gemm, fixture.extract, omitted, &why));

    auto reordered = fixture.wiring;
    BOOST_REQUIRE_GE(reordered.round_order_edges.size(), 2U);
    std::swap(
        reordered.round_order_edges[0],
        reordered.round_order_edges[1]);
    reordered.product_commitment =
        rc::ComputeRCStage3EpisodeWiringProductCommitment(
            reordered);
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeWiringProductSchedule(
        fixture.statement, fixture.manifest,
        fixture.gemm, fixture.extract, reordered, &why));

    auto transcript = fixture.wiring;
    transcript.residual_edges[0].pin.challenge_seed = H(0xe1);
    transcript.residual_edges[0].pin.pin_commitment =
        rc::ComputeRCStage3EpisodeWiringAirPinCommitment(
            transcript.residual_edges[0].pin);
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeWiringProductSchedule(
        fixture.statement, fixture.manifest,
        fixture.gemm, fixture.extract, transcript, &why));

    auto transpose_root = fixture.wiring;
    transpose_root.transpose_edges[0]
        .transposed_vector_root = H(0xe2);
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeWiringProductSchedule(
        fixture.statement, fixture.manifest,
        fixture.gemm, fixture.extract,
        transpose_root, &why));

    auto memory_root = fixture.wiring;
    memory_root.round_order_edges[0]
        .consumer_memory.bundle_commitment = H(0xe3);
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeWiringLocalProduct(
        fixture.statement, fixture.manifest,
        fixture.gemm, fixture.extract,
        memory_root, &why));

    auto source_substitution = fixture.gemm;
    source_substitution.layers[
        fixture.wiring.transpose_edges[0]
            .schedule.layer_ordinal]
        .operand_b[0] = 1;
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeWiringProductSchedule(
        fixture.statement, fixture.manifest,
        source_substitution, fixture.extract,
        fixture.wiring, &why));
}

BOOST_AUTO_TEST_CASE(audit_is_bounded_local_and_fail_closed)
{
    const auto audit =
        rc::CurrentRCStage3EpisodeWiringProductAudit();
    BOOST_CHECK(audit.exact_lambda_transpose_schedule);
    BOOST_CHECK(audit.dual_transpose_permutation_executable);
    BOOST_CHECK(audit.transpose_memory_aliases_executable);
    BOOST_CHECK(audit.exact_residual_schedule);
    BOOST_CHECK(audit.residual_addition_executable);
    BOOST_CHECK(audit.residual_memory_aliases_executable);
    BOOST_CHECK(audit.exact_round_order_schedule);
    BOOST_CHECK(audit.every_producer_consumer_edge_executable);
    BOOST_CHECK(audit.round_order_memory_aliases_executable);
    BOOST_CHECK(
        audit.endpoints_16_through_18_bounded_local_complete);
    BOOST_CHECK(!audit.external_producer_provenance_complete);
    BOOST_CHECK(!audit.production_streaming_complete);
    BOOST_CHECK(!audit.recursively_consumed);
    BOOST_CHECK(!audit.transitively_complete);
}

BOOST_AUTO_TEST_SUITE_END()
