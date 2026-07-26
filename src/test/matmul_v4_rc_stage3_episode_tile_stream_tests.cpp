// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_episode_tile_stream.h>

#include <algorithm>
#include <array>

namespace {

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace gf = rc::gkr_field;
namespace ha = rc::stage3_hash_air;

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
    out.public_inputs.height = 117;
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

std::vector<rc::RCStage3GemmExtractLayerBindings> Bindings(
    const rc::RCEpisodeParams& params)
{
    const auto layout = rc::RCGkrTraceLayout(params);
    std::vector<rc::RCStage3GemmExtractLayerBindings> out(
        layout.layers.size());
    for (uint32_t i = 0; i < out.size(); ++i) {
        auto& b = out[i];
        b.extract_prf = H(0x10 + i);
        b.operand_a_root = H(0x20 + i);
        b.operand_b_root = H(0x30 + i);
        b.gemm_y_root = H(0x40 + i);
        b.extract_input_root = H(0x50 + i);
        b.extract_output_root = H(0x60 + i);
        b.gemm_proof_root = H(0x70 + i);
        b.extract_recursive_root = H(0x80 + i);
        b.scale_schedule_root = H(0x90 + i);
        b.ctl_terminal_root = H(0xa0 + i);
    }
    return out;
}

uint256 ExpectedOutputRoot(
    const std::vector<uint8_t>& stream,
    uint64_t begin,
    uint32_t n_rows,
    uint32_t n_coeffs)
{
    std::vector<gf::Fp3> values(n_rows, gf::Fp3::Zero());
    for (uint32_t i = 0; i < rc::kRCMxBlockLen; ++i) {
        const uint8_t byte = stream[begin + i];
        const int64_t signed_value =
            byte < 128 ? static_cast<int64_t>(byte)
                       : static_cast<int64_t>(byte) - 256;
        values[i] =
            gf::Fp3::FromFp(gf::FromSigned(signed_value));
    }
    return aq::AirCommittedValuesRoot<gf::Fp3>(
        values, n_coeffs);
}

rc::RCStage3EpisodeAirPublicPin TilePin(
    const uint256& statement_commitment,
    const std::vector<uint8_t>& stream,
    uint64_t begin,
    uint8_t salt)
{
    rc::RCStage3EpisodeAirPublicPin pin;
    pin.role = rc::RCStage3RelationRole::EpisodeExtract;
    pin.family =
        rc::RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1;
    pin.statement_commitment = statement_commitment;
    pin.shard_index = 0;
    pin.shard_count = 1;
    // The structural schedule test uses the smallest registry-valid sampler
    // shape. Executed sampler round trips exercise larger rejection traces in
    // the episode-AIR suite.
    pin.logical_rows = rc::kRCMxBlockLen;
    pin.n_rows = rc::kRCMxBlockLen;
    pin.n_coeffs = 128;
    pin.extract_scale_e = salt % 4;
    pin.column_roots.resize(aq::kRcSamplerNumCols);
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        pin.column_roots[i] = {
            i, H(static_cast<uint8_t>(salt + i + 1))};
    }
    pin.column_roots[aq::kColOut].root =
        ExpectedOutputRoot(
            stream, begin, pin.n_rows, pin.n_coeffs);
    return pin;
}

struct Fixture {
    rc::RCStage3SuccinctProof statement{Statement()};
    rc::RCStage3GemmExtractManifest manifest;
    rc::RCStage3EpisodeTileStreamProduct product;
};

bool BuildFixture(Fixture& fixture, std::string* why)
{
    auto params = rc::MakeToyRCEpisodeParams();
    params.L_lyr = 1;
    auto bindings = Bindings(params);
    const uint256 statement_commitment =
        rc::RCStage3EpisodeStatementCommitment(
            fixture.statement);
    const auto built =
        rc::BuildRCStage3GemmExtractManifest(
            params, statement_commitment, bindings, why);
    if (!built.has_value()) return false;
    fixture.manifest = *built;

    auto& product = fixture.product;
    product.statement_commitment = statement_commitment;
    product.expected_rounds = params.rounds;
    product.rounds.resize(params.rounds);

    uint64_t total_tiles = 0;
    for (const auto& layer : fixture.manifest.layers) {
        if (rc::RCStage3EpisodeLayerIsStreamed(layer.kind)) {
            total_tiles += layer.extract_tile_count;
        }
    }
    if (total_tiles > UINT32_MAX) return false;
    product.expected_stream_tiles =
        static_cast<uint32_t>(total_tiles);
    product.tiles.reserve(product.expected_stream_tiles);

    for (uint32_t round_index = 0;
         round_index < params.rounds; ++round_index) {
        uint64_t round_bytes = 0;
        for (const auto& layer : fixture.manifest.layers) {
            if (layer.round == round_index &&
                rc::RCStage3EpisodeLayerIsStreamed(layer.kind)) {
                round_bytes += layer.gemm_cell_count;
            }
        }
        std::vector<uint8_t> stream(round_bytes);
        for (uint64_t i = 0; i < stream.size(); ++i) {
            stream[i] = static_cast<uint8_t>(
                13 * round_index + 29 * i + 137);
        }
        auto& round = product.rounds[round_index];
        round.round_index = round_index;
        round.tree.round_index = round_index;
        if (!ha::BuildTileTreeManifest(
                stream, params.T_leaf,
                round.tree.tree_manifest, why)) {
            return false;
        }
        round.tree.hash_bundle.endpoint =
            rc::RCStage3RelationEndpoint::EpisodeTileTreeRoot;
        round.tree.hash_bundle.statement_commitment =
            statement_commitment;
        round.tree.hash_bundle.manifest_commitment =
            round.tree.tree_manifest.commitment;
        round.stream_memory.endpoint =
            rc::RCStage3RelationEndpoint::EpisodeTileTreeStream;
        round.stream_memory.statement_commitment =
            statement_commitment;
        round.stream_memory.total_instance_count = stream.size();
        round.stream_memory.address_begin =
            UINT64_C(0x4553000000000000) +
            static_cast<uint64_t>(round_index) *
                (UINT64_C(1) << 40);
        round.stream_memory.address_stride = 1;
        round.stream_memory.bundle_commitment =
            H(static_cast<uint8_t>(0xe0 + round_index));

        uint64_t stream_byte = 0;
        for (uint32_t layer_ordinal = 0;
             layer_ordinal < fixture.manifest.layers.size();
             ++layer_ordinal) {
            auto& layer =
                fixture.manifest.layers[layer_ordinal];
            if (layer.round != round_index ||
                !rc::RCStage3EpisodeLayerIsStreamed(
                    layer.kind)) {
                continue;
            }
            std::vector<uint256> roots;
            roots.reserve(layer.extract_tile_count);
            for (uint64_t layer_tile = 0;
                 layer_tile < layer.extract_tile_count;
                 ++layer_tile) {
                rc::RCStage3EpisodeTileStreamShard tile;
                tile.global_stream_tile =
                    product.tiles.size();
                tile.layer_ordinal = layer_ordinal;
                tile.layer_tile_index = layer_tile;
                tile.stream_byte_begin = stream_byte;
                tile.pin = TilePin(
                    statement_commitment, stream, stream_byte,
                    static_cast<uint8_t>(
                        tile.global_stream_tile + 1));
                roots.push_back(
                    tile.pin.column_roots[aq::kColOut].root);
                product.tiles.push_back(std::move(tile));
                stream_byte += rc::kRCMxBlockLen;
            }
            layer.bindings.extract_output_root =
                rc::ComputeRCStage3EpisodeStreamedLayerOutputRoot(
                    fixture.manifest, layer_ordinal, roots);
            if (layer.bindings.extract_output_root.IsNull()) {
                return false;
            }
        }
        if (stream_byte != stream.size()) return false;
    }

    product.gemm_extract_manifest_commitment =
        rc::ComputeRCStage3GemmExtractManifestCommitment(
            fixture.manifest);
    product.collection_commitment =
        rc::ComputeRCStage3EpisodeTileStreamCollectionCommitment(
            product);
    return !product.collection_commitment.IsNull();
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_episode_tile_stream_tests)

BOOST_AUTO_TEST_CASE(
    exact_schedule_maps_every_tile_and_rejects_omission_order_and_bytes)
{
    Fixture fixture;
    std::string why;
    BOOST_REQUIRE_MESSAGE(BuildFixture(fixture, &why), why);
    BOOST_REQUIRE_MESSAGE(
        rc::ValidateRCStage3EpisodeTileStreamSchedule(
            fixture.statement, fixture.manifest,
            fixture.product, &why),
        why);

    auto omitted = fixture.product;
    omitted.tiles.pop_back();
    omitted.collection_commitment =
        rc::ComputeRCStage3EpisodeTileStreamCollectionCommitment(
            omitted);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeTileStreamSchedule(
            fixture.statement, fixture.manifest,
            omitted, &why));

    auto reordered = fixture.product;
    std::swap(reordered.tiles[0], reordered.tiles[1]);
    reordered.collection_commitment =
        rc::ComputeRCStage3EpisodeTileStreamCollectionCommitment(
            reordered);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeTileStreamSchedule(
            fixture.statement, fixture.manifest,
            reordered, &why));

    auto changed_byte = fixture.product;
    changed_byte.rounds[0].tree.tree_manifest.stream[0] ^= 1;
    changed_byte.rounds[0].tree.tree_manifest.commitment =
        ha::CommitTileTreeManifest(
            changed_byte.rounds[0].tree.tree_manifest);
    changed_byte.rounds[0].tree.hash_bundle.manifest_commitment =
        changed_byte.rounds[0].tree.tree_manifest.commitment;
    changed_byte.collection_commitment =
        rc::ComputeRCStage3EpisodeTileStreamCollectionCommitment(
            changed_byte);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeTileStreamSchedule(
            fixture.statement, fixture.manifest,
            changed_byte, &why));

    auto changed_root = fixture.product;
    changed_root.rounds[0].tree.tree_manifest.root = H(0xf6);
    changed_root.rounds[0].tree.tree_manifest.commitment =
        ha::CommitTileTreeManifest(
            changed_root.rounds[0].tree.tree_manifest);
    changed_root.rounds[0].tree.hash_bundle.manifest_commitment =
        changed_root.rounds[0].tree.tree_manifest.commitment;
    changed_root.collection_commitment =
        rc::ComputeRCStage3EpisodeTileStreamCollectionCommitment(
            changed_root);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeTileStreamSchedule(
            fixture.statement, fixture.manifest,
            changed_root, &why));

    auto changed_output = fixture.product;
    changed_output.tiles[0]
        .pin.column_roots[aq::kColOut].root = H(0xf7);
    changed_output.collection_commitment =
        rc::ComputeRCStage3EpisodeTileStreamCollectionCommitment(
            changed_output);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeTileStreamSchedule(
            fixture.statement, fixture.manifest,
            changed_output, &why));
}

BOOST_AUTO_TEST_CASE(
    streamed_layer_filter_matches_consensus_round_emission)
{
    BOOST_CHECK(rc::RCStage3EpisodeLayerIsStreamed(
        rc::RCGkrLayerKind::GemmPhase1SV));
    BOOST_CHECK(rc::RCStage3EpisodeLayerIsStreamed(
        rc::RCGkrLayerKind::GemmPhase2Fwd));
    BOOST_CHECK(!rc::RCStage3EpisodeLayerIsStreamed(
        rc::RCGkrLayerKind::GemmPhase1QKt));
    BOOST_CHECK(!rc::RCStage3EpisodeLayerIsStreamed(
        rc::RCGkrLayerKind::GemmPhase2FfnUp));
    BOOST_CHECK(!rc::kRCSegmentLeavesEnabled);
}

BOOST_AUTO_TEST_CASE(
    audit_is_local_complete_and_fail_closed_transitively)
{
    const auto audit =
        rc::CurrentRCStage3EpisodeTileStreamAudit();
    BOOST_CHECK(audit.verifier_derived_emission_schedule);
    BOOST_CHECK(audit.every_streamed_extract_shard_executed);
    BOOST_CHECK(audit.extract_out_to_stream_byte_equality);
    BOOST_CHECK(audit.proof_owned_stream_memory_executed);
    BOOST_CHECK(
        audit.stream_to_leaf_same_trace_ctl_executable);
    BOOST_CHECK(audit.every_leaf_hash_executed);
    BOOST_CHECK(
        audit.leaf_to_internal_same_trace_ctl_executable);
    BOOST_CHECK(audit.every_internal_hash_executed);
    BOOST_CHECK(
        audit.internal_to_typed_root_same_trace_ctl_executable);
    BOOST_CHECK(audit.canonical_round_root_derived);
    BOOST_CHECK(
        audit.endpoints_19_through_22_locally_complete);
    BOOST_CHECK(
        !audit.all_extract_inputs_and_gemm_provenance_complete);
    BOOST_CHECK(!audit.recursively_consumed);
    BOOST_CHECK(!audit.transitively_complete);
    BOOST_CHECK(!audit.remaining.empty());
}

BOOST_AUTO_TEST_SUITE_END()
