// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_gkr_air.h>
#include <matmul/matmul_v4_rc_stage3_episode_extract_product.h>
#include <matmul/matmul_v4_rc_stage3_extract_stream_ctl.h>
#include <matmul/matmul_v4_rc_stage3_tile_tree_hash_ctl.h>

#include <algorithm>
#include <array>
#include <cstdlib>

namespace {

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace ga = rc::gkr_air;
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
    out.public_inputs.height = 131;
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

uint256 BinaryRoot(uint8_t value, uint32_t n_coeffs)
{
    std::vector<gf::Fp3> values(
        rc::kRCMxBlockLen,
        gf::Fp3::FromFp(gf::FromU64(value)));
    return aq::AirCommittedValuesRoot<gf::Fp3>(
        values, n_coeffs);
}

std::vector<uint8_t> ScalePreimage(
    const uint256& prf, uint32_t row, uint32_t block)
{
    constexpr char tag[] = "BTX_MATEXPAND_MXSCALE_V44LT";
    std::vector<uint8_t> out(tag, tag + sizeof(tag) - 1);
    out.insert(out.end(), prf.begin(), prf.end());
    for (uint32_t value : {row, block}) {
        for (unsigned i = 0; i < 4; ++i) {
            out.push_back(value >> (8 * i));
        }
    }
    return out;
}

rc::RCStage3EpisodeAirPublicPin SamplerPin(
    const uint256& statement_commitment,
    const uint256& zero_root)
{
    rc::RCStage3EpisodeAirPublicPin pin;
    pin.role = rc::RCStage3RelationRole::EpisodeExtract;
    pin.family =
        rc::RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1;
    pin.statement_commitment = statement_commitment;
    pin.shard_count = 1;
    pin.logical_rows = rc::kRCMxBlockLen;
    pin.n_rows = rc::kRCMxBlockLen;
    pin.n_coeffs = 128;
    pin.extract_scale_e = 0;
    pin.column_roots.resize(aq::kRcSamplerNumCols);
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        pin.column_roots[i] = {
            i, H(static_cast<uint8_t>(0x31 + i))};
    }
    for (uint32_t column : {
             aq::kColKappa, aq::kColH, aq::kColPos,
             aq::kColUMix, aq::kColGoldQ, aq::kColGoldV,
             aq::kColOut}) {
        pin.column_roots[column].root = zero_root;
    }
    return pin;
}

struct Fixture {
    rc::RCStage3SuccinctProof statement{Statement()};
    rc::RCStage3GemmExtractManifest manifest;
    rc::RCStage3EpisodeExtractProduct extract;
    rc::RCStage3EpisodeTileStreamProduct stream;
};

bool BuildFixture(Fixture& fixture, std::string* why)
{
    const auto params = TinyParams();
    const uint256 statement_commitment =
        rc::RCStage3EpisodeStatementCommitment(
            fixture.statement);
    const auto built = rc::BuildRCStage3GemmExtractManifest(
        params, statement_commitment, Bindings(params), why);
    if (!built.has_value()) return false;
    fixture.manifest = *built;

    const uint256 zero128 = BinaryRoot(0, 128);
    const uint256 zero32 = BinaryRoot(0, 32);
    const uint256 one128 = BinaryRoot(1, 128);

    auto& product = fixture.extract;
    product.statement_commitment = statement_commitment;
    product.expected_tiles =
        fixture.manifest.total_extract_tiles;
    product.tiles.reserve(product.expected_tiles);

    for (uint32_t layer_ordinal = 0;
         layer_ordinal < fixture.manifest.layers.size();
         ++layer_ordinal) {
        auto& layer = fixture.manifest.layers[layer_ordinal];
        const uint32_t blocks_per_row =
            layer.n / rc::kRCMxBlockLen;
        std::vector<uint256> input_roots;
        std::vector<uint256> output_roots;
        std::vector<uint256> scale_roots;
        std::vector<uint256> receipts;
        for (uint64_t local = 0;
             local < layer.extract_tile_count; ++local) {
            const uint32_t row = local / blocks_per_row;
            const uint32_t block = local % blocks_per_row;
            rc::RCStage3EpisodeExtractTileProduct tile;
            tile.global_tile = product.tiles.size();
            tile.layer_ordinal = layer_ordinal;
            tile.layer_tile_index = local;
            tile.candidate_positions.assign(
                rc::kRCMxBlockLen, 0);
            tile.sampler_pin =
                SamplerPin(statement_commitment, zero128);

            tile.chacha_manifest.key = {};
            std::copy_n(
                layer.bindings.extract_prf.begin(), 32,
                tile.chacha_manifest.key.begin());
            tile.chacha_manifest.nonce_first =
                block ^ 0x4D58424CU;
            tile.chacha_manifest.nonce_second =
                (static_cast<uint64_t>(row) << 32) | block;
            tile.chacha_manifest.output_bytes = 64;
            tile.chacha_manifest.blocks.resize(1);
            tile.chacha_manifest.output.assign(64, 0);
            tile.chacha_manifest.commitment =
                ha::CommitChaChaConsumptionManifest(
                    tile.chacha_manifest);
            tile.chacha.proofs.endpoint =
                rc::RCStage3RelationEndpoint::EpisodeExtractChaCha;
            tile.chacha.proofs.statement_commitment =
                statement_commitment;
            tile.chacha.proofs.manifest_commitment =
                tile.chacha_manifest.commitment;

            tile.scale_manifest.mode = ha::ShaMode::Single;
            tile.scale_manifest.preimage =
                ScalePreimage(
                    layer.bindings.extract_prf, row, block);
            tile.scale_manifest.digest.fill(0);
            tile.scale_manifest.commitment =
                ha::CommitShaManifest(tile.scale_manifest);
            tile.scale.proofs.endpoint =
                rc::RCStage3RelationEndpoint::EpisodeExtractScale;
            tile.scale.proofs.statement_commitment =
                statement_commitment;
            tile.scale.proofs.manifest_commitment =
                tile.scale_manifest.commitment;

            auto& mix = tile.mix_pin;
            mix.statement_commitment = statement_commitment;
            mix.layer_ordinal = layer_ordinal;
            mix.layer_tile_index = local;
            mix.logical_rows = rc::kRCMxBlockLen;
            mix.n_rows = rc::kRCMxBlockLen;
            mix.n_coeffs = 128;
            mix.column_roots.resize(
                rc::kRCStage3EpisodeExtractMixColumns);
            for (uint32_t i = 0;
                 i < mix.column_roots.size(); ++i) {
                mix.column_roots[i] = {
                    i, H(static_cast<uint8_t>(
                           1 + ((0x61U + i) % 254U)))};
            }
            for (uint32_t column : {
                     rc::kRCStage3ExtractMixU,
                     rc::kRCStage3ExtractMixQ,
                     rc::kRCStage3ExtractMixV,
                     rc::kRCStage3ExtractMixH}) {
                mix.column_roots[column].root = zero128;
            }
            mix.column_roots[
                rc::kRCStage3ExtractMixBranch].root = one128;
            for (uint32_t bit = 0; bit < 32; ++bit) {
                mix.column_roots[
                    rc::kRCStage3ExtractMixYLoBits + bit].root =
                    zero128;
                mix.column_roots[
                    rc::kRCStage3ExtractMixYHiBits + bit].root =
                    zero128;
            }
            mix.pin_commitment =
                rc::ComputeRCStage3EpisodeExtractMixPinCommitment(
                    mix);

            tile.tile_receipt_commitment =
                rc::ComputeRCStage3EpisodeExtractTileReceiptCommitment(
                    tile);
            input_roots.push_back(
                rc::ComputeRCStage3EpisodeExtractInputTileRoot(
                    tile.input));
            output_roots.push_back(zero128);
            scale_roots.push_back(
                tile.scale_manifest.commitment);
            receipts.push_back(
                tile.tile_receipt_commitment);
            product.tiles.push_back(std::move(tile));
        }
        layer.bindings.extract_input_root =
            rc::ComputeRCStage3EpisodeExtractInputLayerRoot(
                fixture.manifest, layer_ordinal, input_roots);
        layer.bindings.extract_output_root =
            rc::ComputeRCStage3EpisodeStreamedLayerOutputRoot(
                fixture.manifest, layer_ordinal, output_roots);
        layer.bindings.scale_schedule_root =
            rc::ComputeRCStage3EpisodeExtractScaleLayerRoot(
                fixture.manifest, layer_ordinal, scale_roots);
        layer.bindings.extract_recursive_root =
            rc::ComputeRCStage3EpisodeExtractRecursiveLayerRoot(
                fixture.manifest, layer_ordinal, receipts);
    }

    product.manifest_commitment =
        rc::ComputeRCStage3GemmExtractManifestCommitment(
            fixture.manifest);
    product.collection_commitment =
        rc::ComputeRCStage3EpisodeExtractCollectionCommitment(
            product);

    auto& stream = fixture.stream;
    stream.statement_commitment = statement_commitment;
    stream.gemm_extract_manifest_commitment =
        product.manifest_commitment;
    stream.expected_rounds = params.rounds;
    stream.expected_stream_tiles = 0;
    uint64_t round_bytes = 0;
    for (const auto& layer : fixture.manifest.layers) {
        if (rc::RCStage3EpisodeLayerIsStreamed(layer.kind)) {
            stream.expected_stream_tiles +=
                layer.extract_tile_count;
            round_bytes += layer.gemm_cell_count;
        }
    }
    stream.rounds.resize(1);
    auto& round = stream.rounds[0];
    round.round_index = 0;
    round.tree.round_index = 0;
    if (!ha::BuildTileTreeManifest(
            std::vector<uint8_t>(round_bytes, 0),
            params.T_leaf, round.tree.tree_manifest, why)) {
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
    round.stream_memory.total_instance_count = round_bytes;
    round.stream_memory.address_begin =
        UINT64_C(0x4553000000000000);
    round.stream_memory.address_stride = 1;
    round.stream_memory.bundle_commitment = H(0xee);

    uint64_t stream_byte = 0;
    for (const auto& layer : fixture.manifest.layers) {
        if (!rc::RCStage3EpisodeLayerIsStreamed(layer.kind)) {
            continue;
        }
        for (uint64_t local = 0;
             local < layer.extract_tile_count; ++local) {
            rc::RCStage3EpisodeTileStreamShard tile;
            tile.global_stream_tile = stream.tiles.size();
            tile.layer_ordinal = layer.ordinal;
            tile.layer_tile_index = local;
            tile.stream_byte_begin = stream_byte;
            tile.pin = product.tiles[
                layer.extract_tile_begin + local].sampler_pin;
            stream.tiles.push_back(std::move(tile));
            stream_byte += rc::kRCMxBlockLen;
        }
    }
    stream.collection_commitment =
        rc::ComputeRCStage3EpisodeTileStreamCollectionCommitment(
            stream);
    (void)zero32;
    return !product.collection_commitment.IsNull() &&
           !stream.collection_commitment.IsNull();
}

void RefreshTile(
    rc::RCStage3EpisodeExtractProduct& product,
    uint64_t tile_index)
{
    auto& tile = product.tiles[tile_index];
    tile.tile_receipt_commitment =
        rc::ComputeRCStage3EpisodeExtractTileReceiptCommitment(
            tile);
    product.collection_commitment =
        rc::ComputeRCStage3EpisodeExtractCollectionCommitment(
            product);
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_episode_extract_product_tests)

BOOST_AUTO_TEST_CASE(
    audit_separates_local_transitive_and_recursive_completion)
{
    const auto audit =
        rc::CurrentRCStage3EpisodeExtractProductAudit();
    BOOST_CHECK(audit.exact_all_tile_schedule);
    BOOST_CHECK(audit.input_opening_and_mix_air_executed);
    BOOST_CHECK(audit.sampler_walk_executed);
    BOOST_CHECK(audit.chacha_consumption_air_executed);
    BOOST_CHECK(audit.scale_sha_air_executed);
    BOOST_CHECK(audit.dequant_output_root_bound);
    BOOST_CHECK(audit.endpoint19_equality_executed);
    BOOST_CHECK(audit.endpoints_10_through_14_locally_complete);
    BOOST_CHECK(
        !audit.gemm_output_producer_transitively_complete);
    BOOST_CHECK(!audit.recursively_consumed);
    BOOST_CHECK(!audit.transitively_complete);
}

BOOST_AUTO_TEST_CASE(
    mix_air_executes_signed_input_projection_and_rejects_root_substitution)
{
    constexpr uint32_t N = rc::kRCMxBlockLen;
    std::vector<std::vector<gf::Fp3>> columns(
        rc::kRCStage3EpisodeExtractMixColumns,
        std::vector<gf::Fp3>(N, gf::Fp3::Zero()));
    for (uint32_t r = 0; r < N; ++r) {
        columns[rc::kRCStage3ExtractMixBranch][r] =
            gf::Fp3::One();
        for (uint32_t bit = 0; bit < 32; ++bit) {
            columns[
                rc::kRCStage3ExtractMixQDifferenceBits + bit][r] =
                gf::Fp3::FromFp(
                    gf::FromU64((0x9E3779B9U >> bit) & 1));
        }
    }

    rc::RCStage3EpisodeExtractMixPin pin;
    pin.statement_commitment = H(0x17);
    pin.layer_ordinal = 2;
    pin.layer_tile_index = 3;
    pin.logical_rows = N;
    pin.n_rows = N;
    pin.n_coeffs = 128;
    for (uint32_t column = 0;
         column < columns.size(); ++column) {
        pin.column_roots.push_back({
            column,
            aq::AirCommittedValuesRoot<gf::Fp3>(
                columns[column], pin.n_coeffs)});
    }
    pin.pin_commitment =
        rc::ComputeRCStage3EpisodeExtractMixPinCommitment(pin);
    BOOST_REQUIRE(!pin.pin_commitment.IsNull());

    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeExtractMixConstraintSystem(
            pin, cs, &why),
        why);
    const auto proved = aq::AirQuotientProve<gf::Fp3>(
        cs, columns,
        rc::ComputeRCStage3EpisodeExtractMixSeed(pin));
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeExtractMixProof(
            pin, proved.proof, &why),
        why);

    auto changed = pin;
    changed.column_roots[
        rc::kRCStage3ExtractMixU].root = H(0xfa);
    changed.pin_commitment =
        rc::ComputeRCStage3EpisodeExtractMixPinCommitment(changed);
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeExtractMixProof(
        changed, proved.proof, &why));
}

BOOST_AUTO_TEST_CASE(
    exact_schedule_rejects_omission_order_root_scale_and_chacha_substitution)
{
    Fixture fixture;
    std::string why;
    BOOST_REQUIRE_MESSAGE(BuildFixture(fixture, &why), why);
    BOOST_REQUIRE_MESSAGE(
        rc::ValidateRCStage3EpisodeExtractSchedule(
            fixture.statement, fixture.manifest,
            fixture.extract, fixture.stream, &why),
        why);

    auto vertical_identity = fixture.extract;
    vertical_identity.vertical_hash_proofs = true;
    vertical_identity.vertical_chacha.endpoint =
        rc::RCStage3RelationEndpoint::EpisodeExtractChaCha;
    vertical_identity.vertical_scale.endpoint =
        rc::RCStage3RelationEndpoint::EpisodeExtractScale;
    vertical_identity.vertical_chacha.statement_commitment =
        vertical_identity.statement_commitment;
    vertical_identity.vertical_scale.statement_commitment =
        vertical_identity.statement_commitment;
    BOOST_REQUIRE_MESSAGE(
        rc::ValidateRCStage3EpisodeExtractSchedule(
            fixture.statement, fixture.manifest,
            vertical_identity, fixture.stream, &why),
        why);
    auto wrong_vertical_endpoint = vertical_identity;
    wrong_vertical_endpoint.vertical_chacha.endpoint =
        rc::RCStage3RelationEndpoint::EpisodeExtractScale;
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeExtractSchedule(
        fixture.statement, fixture.manifest,
        wrong_vertical_endpoint, fixture.stream, &why));
    auto wrong_vertical_statement = vertical_identity;
    wrong_vertical_statement.vertical_scale.statement_commitment =
        H(0xfa);
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeExtractSchedule(
        fixture.statement, fixture.manifest,
        wrong_vertical_statement, fixture.stream, &why));

    auto omitted = fixture.extract;
    omitted.tiles.pop_back();
    omitted.collection_commitment =
        rc::ComputeRCStage3EpisodeExtractCollectionCommitment(
            omitted);
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeExtractSchedule(
        fixture.statement, fixture.manifest,
        omitted, fixture.stream, &why));

    auto reordered = fixture.extract;
    std::swap(reordered.tiles[0], reordered.tiles[1]);
    reordered.collection_commitment =
        rc::ComputeRCStage3EpisodeExtractCollectionCommitment(
            reordered);
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeExtractSchedule(
        fixture.statement, fixture.manifest,
        reordered, fixture.stream, &why));

    auto root_substitution = fixture.extract;
    root_substitution.tiles[0]
        .sampler_pin.column_roots[aq::kColOut].root = H(0xf1);
    RefreshTile(root_substitution, 0);
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeExtractSchedule(
        fixture.statement, fixture.manifest,
        root_substitution, fixture.stream, &why));

    auto scale_substitution = fixture.extract;
    scale_substitution.tiles[0].scale_manifest.digest[0] = 1;
    scale_substitution.tiles[0].scale_manifest.commitment =
        ha::CommitShaManifest(
            scale_substitution.tiles[0].scale_manifest);
    scale_substitution.tiles[0]
        .scale.proofs.manifest_commitment =
        scale_substitution.tiles[0].scale_manifest.commitment;
    RefreshTile(scale_substitution, 0);
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeExtractSchedule(
        fixture.statement, fixture.manifest,
        scale_substitution, fixture.stream, &why));

    auto chacha_substitution = fixture.extract;
    chacha_substitution.tiles[0].chacha_manifest.output[0] = 1;
    chacha_substitution.tiles[0]
        .chacha_manifest.blocks[0][0] = 1;
    chacha_substitution.tiles[0].chacha_manifest.commitment =
        ha::CommitChaChaConsumptionManifest(
            chacha_substitution.tiles[0].chacha_manifest);
    chacha_substitution.tiles[0]
        .chacha.proofs.manifest_commitment =
        chacha_substitution.tiles[0].chacha_manifest.commitment;
    RefreshTile(chacha_substitution, 0);
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeExtractSchedule(
        fixture.statement, fixture.manifest,
        chacha_substitution, fixture.stream, &why));
}

BOOST_AUTO_TEST_CASE(
    extract_output_to_stream_memory_selected_ctl_executes_and_mutations_reject)
{
    const auto statement = Statement();
    const auto params = TinyParams();
    std::string why;
    auto manifest = rc::BuildRCStage3GemmExtractManifest(
        params, rc::RCStage3EpisodeStatementCommitment(statement),
        Bindings(params), &why);
    BOOST_REQUIRE_MESSAGE(manifest.has_value(), why);
    const auto layer_it = std::find_if(
        manifest->layers.begin(), manifest->layers.end(),
        [](const auto& layer) {
            return rc::RCStage3EpisodeLayerIsStreamed(
                layer.kind);
        });
    BOOST_REQUIRE(layer_it != manifest->layers.end());
    const uint32_t layer_ordinal =
        static_cast<uint32_t>(
            layer_it - manifest->layers.begin());
    std::array<int64_t, rc::kRCMxBlockLen> input{};
    for (uint32_t i = 0; i < input.size(); ++i) {
        input[i] = static_cast<int64_t>(i) - 16;
    }
    const ga::TilePublic tile_public{
        layer_it->bindings.extract_prf, 0, 0};
    const ga::TileWitness witness =
        ga::TraceTile(tile_public, input);
    BOOST_REQUIRE(!witness.cands.empty());
    const ga::TableTM table;

    rc::RCStage3EpisodeExtractTileProduct tile;
    tile.global_tile = 0;
    tile.layer_ordinal = layer_ordinal;
    tile.layer_tile_index = 0;
    tile.input = input;
    auto& pin = tile.sampler_pin;
    pin.role = rc::RCStage3RelationRole::EpisodeExtract;
    pin.family =
        rc::RCStage3EpisodeAirFamily::
            ExtractSamplerCoreFp3V1;
    pin.statement_commitment =
        rc::RCStage3EpisodeStatementCommitment(statement);
    pin.shard_count = 1;
    pin.logical_rows = witness.cands.size();
    pin.n_rows = rc::FriNextPow2(std::max<uint32_t>(
        pin.logical_rows, rc::kRCMxBlockLen + 1));
    const auto dummy =
        aq::BuildRcSamplerConstraintSystem<gf::Fp3>(
            pin.n_rows, gf::Fp3::Zero(),
            gf::Fp3::Zero(), witness.scale_e, table);
    pin.n_coeffs = rc::FriNextPow2(std::max(
        pin.n_rows, dummy.QuotientLen()));
    pin.extract_scale_e = witness.scale_e;
    pin.column_roots.resize(aq::kRcSamplerNumCols);
    const uint256 sampler_seed =
        rc::ComputeRCStage3EpisodeAirSeed(statement, pin);
    const auto sampler =
        aq::BuildRcSamplerInstance<gf::Fp3>(
            witness, table, sampler_seed);
    BOOST_REQUIRE_MESSAGE(sampler.ok, sampler.note);
    for (uint32_t column = 0;
         column < sampler.columns.size(); ++column) {
        pin.column_roots[column] = {
            column,
            aq::AirCommittedValuesRoot<gf::Fp3>(
                sampler.columns[column],
                pin.n_coeffs)};
    }

    rc::RCStage3EpisodeExtractProduct extract;
    extract.collection_commitment = H(0xa1);
    extract.tiles.push_back(tile);
    rc::RCStage3EpisodeTileStreamProduct stream;
    stream.collection_commitment = H(0xa2);
    rc::RCStage3EpisodeTileStreamShard stream_tile;
    stream_tile.global_stream_tile = 0;
    stream_tile.layer_ordinal = layer_ordinal;
    stream_tile.layer_tile_index = 0;
    stream_tile.pin = pin;
    stream.tiles.push_back(stream_tile);
    stream.rounds.resize(1);
    stream.rounds[0].tree.tree_manifest.stream.reserve(
        rc::kRCMxBlockLen);
    std::vector<gf::Fp3> memory_values;
    memory_values.reserve(rc::kRCMxBlockLen);
    for (int8_t value : witness.out) {
        stream.rounds[0].tree.tree_manifest.stream.push_back(
            static_cast<uint8_t>(value));
        memory_values.push_back(
            gf::Fp3::FromFp(gf::FromSigned(value)));
    }
    const auto memory_root =
        rc::ComputeRCStage3EpisodeSemanticValueRoot(
            memory_values, rc::kRCMxBlockLen,
            rc::kRCMxBlockLen, &why);
    BOOST_REQUIRE_MESSAGE(memory_root.has_value(), why);
    const auto memory_manifest =
        rc::BuildRCStage3EpisodeSemanticMemoryManifest(
            rc::RCStage3RelationEndpoint::EpisodeTileTreeStream,
            pin.statement_commitment, rc::kRCMxBlockLen,
            rc::kRCMxBlockLen,
            UINT64_C(0x4553000000000000), 1,
            *memory_root, &why);
    BOOST_REQUIRE_MESSAGE(memory_manifest.has_value(), why);
    rc::RCStage3EpisodeSemanticMemoryShard memory_shard;
    memory_shard.manifest = *memory_manifest;
    stream.rounds[0].stream_memory.shards.push_back(
        memory_shard);

    rc::RCStage3ExtractStreamCtlTileProof proof;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3ExtractStreamCtlTile(
            statement, *manifest, extract, stream,
            0, proof, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3ExtractStreamCtlTile(
            statement, *manifest, extract, stream,
            0, proof, &why),
        why);

    auto source_root = proof;
    source_root.sampler_output_root = H(0xb1);
    BOOST_CHECK(
        !rc::VerifyRCStage3ExtractStreamCtlTile(
            statement, *manifest, extract, stream,
            0, source_root, &why));
    auto memory_root_mutation = proof;
    memory_root_mutation.memory_value_root = H(0xb2);
    BOOST_CHECK(
        !rc::VerifyRCStage3ExtractStreamCtlTile(
            statement, *manifest, extract, stream,
            0, memory_root_mutation, &why));
    auto transcript = proof;
    transcript.pins[0].trace_commitment = H(0xb3);
    BOOST_CHECK(
        !rc::VerifyRCStage3ExtractStreamCtlTile(
            statement, *manifest, extract, stream,
            0, transcript, &why));
}

BOOST_AUTO_TEST_CASE(
    honest_all_tile_extract_and_stream_products_execute)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_EPISODE_EXTRACT_PRODUCT_PROVE") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_EPISODE_EXTRACT_PRODUCT_PROVE=1 "
            "for the complete all-tile Extract/stream/tree round trip");
        return;
    }
    const auto statement = Statement();
    auto params = TinyParams();
    // Two leaves exercise both leaf->internal and internal->typed-root
    // proof-owned SHA CTLs without turning this opt-in test into a
    // production-size prover benchmark.
    params.T_leaf = 1024;
    std::string why;
    auto manifest = rc::BuildRCStage3GemmExtractManifest(
        params, rc::RCStage3EpisodeStatementCommitment(statement),
        Bindings(params), &why);
    BOOST_REQUIRE_MESSAGE(manifest.has_value(), why);
    std::vector<std::array<int64_t, rc::kRCMxBlockLen>> inputs(
        manifest->total_extract_tiles);
    for (uint64_t tile = 0; tile < inputs.size(); ++tile) {
        for (uint32_t cell = 0; cell < rc::kRCMxBlockLen; ++cell) {
            inputs[tile][cell] =
                static_cast<int64_t>((tile * 31 + cell) % 97) - 48;
        }
    }
    rc::RCStage3EpisodeExtractProduct extract;
    rc::RCStage3EpisodeTileStreamProduct stream;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeExtractAndTileStreamProducts(
            statement, *manifest, inputs, extract, stream, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeExtractProduct(
            statement, *manifest, extract, stream, &why),
        why);
    rc::RCStage3ExtractStreamCtlProof extract_stream_ctl;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3ExtractStreamCtl(
            statement, *manifest, extract, stream,
            extract_stream_ctl, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3ExtractStreamCtl(
            statement, *manifest, extract, stream,
            extract_stream_ctl, &why),
        why);
    BOOST_REQUIRE(!extract_stream_ctl.tiles.empty());

    auto changed_extract_stream_source =
        extract_stream_ctl;
    changed_extract_stream_source.tiles[0]
        .sampler_output_root = H(0xb1);
    BOOST_CHECK(
        !rc::VerifyRCStage3ExtractStreamCtl(
            statement, *manifest, extract, stream,
            changed_extract_stream_source, &why));

    auto changed_extract_stream_memory =
        extract_stream_ctl;
    changed_extract_stream_memory.tiles[0]
        .memory_value_root = H(0xb2);
    BOOST_CHECK(
        !rc::VerifyRCStage3ExtractStreamCtl(
            statement, *manifest, extract, stream,
            changed_extract_stream_memory, &why));

    auto changed_extract_stream_transcript =
        extract_stream_ctl;
    changed_extract_stream_transcript.tiles[0]
        .pins[0].trace_commitment = H(0xb3);
    BOOST_CHECK(
        !rc::VerifyRCStage3ExtractStreamCtl(
            statement, *manifest, extract, stream,
            changed_extract_stream_transcript, &why));

    rc::RCStage3EpisodeTileStreamLeafCtlProof leaf_ctl;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeTileStreamLeafCtl(
            statement, *manifest, stream, leaf_ctl, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3EpisodeTileStreamLeafCtl(
            statement, *manifest, stream, leaf_ctl, &why),
        why);
    BOOST_REQUIRE(!leaf_ctl.shards.empty());

    rc::RCStage3TileTreeHashCtlProof hash_ctl;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3TileTreeHashCtl(
            statement, *manifest, stream, hash_ctl, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3TileTreeHashCtl(
            statement, *manifest, stream, hash_ctl, &why),
        why);
    BOOST_REQUIRE_EQUAL(hash_ctl.edges.size(), 3U);
    BOOST_CHECK(
        hash_ctl.edges[0].producer_endpoint ==
        rc::RCStage3RelationEndpoint::
            EpisodeTileTreeLeafHash);
    BOOST_CHECK(
        hash_ctl.edges.back().consumer_endpoint ==
        rc::RCStage3RelationEndpoint::
            EpisodeTileTreeRoot);

    auto changed_hash_source_root = hash_ctl;
    changed_hash_source_root.edges[0].producer_r0_root =
        H(0xc1);
    BOOST_CHECK(
        !rc::VerifyRCStage3TileTreeHashCtl(
            statement, *manifest, stream,
            changed_hash_source_root, &why));

    auto changed_hash_sink_root = hash_ctl;
    changed_hash_sink_root.edges.back().consumer_r0_root =
        H(0xc2);
    BOOST_CHECK(
        !rc::VerifyRCStage3TileTreeHashCtl(
            statement, *manifest, stream,
            changed_hash_sink_root, &why));

    auto changed_hash_transcript = hash_ctl;
    changed_hash_transcript.edges[0]
        .pins[0].trace_commitment = H(0xc3);
    BOOST_CHECK(
        !rc::VerifyRCStage3TileTreeHashCtl(
            statement, *manifest, stream,
            changed_hash_transcript, &why));

    auto changed_hash_producer_proof = hash_ctl;
    BOOST_REQUIRE(
        !changed_hash_producer_proof.edges[0]
             .producer_proof.batch.groups.empty());
    const auto changed_producer_digest =
        rc::Fri3AlgDigestFromUint256(H(0xc4));
    BOOST_REQUIRE(changed_producer_digest.has_value());
    changed_hash_producer_proof.edges[0]
        .producer_proof.batch.groups[0]
        .row_commit.root =
        *changed_producer_digest;
    BOOST_CHECK(
        !rc::VerifyRCStage3TileTreeHashCtl(
            statement, *manifest, stream,
            changed_hash_producer_proof, &why));

    auto changed_hash_consumer_proof = hash_ctl;
    BOOST_REQUIRE(
        !changed_hash_consumer_proof.edges.back()
             .consumer_proof.batch.groups.empty());
    const auto changed_consumer_digest =
        rc::Fri3AlgDigestFromUint256(H(0xc5));
    BOOST_REQUIRE(changed_consumer_digest.has_value());
    changed_hash_consumer_proof.edges.back()
        .consumer_proof.batch.groups[0]
        .row_commit.root =
        *changed_consumer_digest;
    BOOST_CHECK(
        !rc::VerifyRCStage3TileTreeHashCtl(
            statement, *manifest, stream,
            changed_hash_consumer_proof, &why));

    auto changed_ctl_pin = leaf_ctl;
    changed_ctl_pin.shards[0].bridge_pin.value_root = H(0xd1);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeTileStreamLeafCtl(
            statement, *manifest, stream,
            changed_ctl_pin, &why));

    auto changed_ctl_producer = leaf_ctl;
    changed_ctl_producer.shards[0]
        .producer_product.batch.columns[
            rc::kRCStage3EpisodeMemoryExport].root = H(0xd2);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeTileStreamLeafCtl(
            statement, *manifest, stream,
            changed_ctl_producer, &why));

    auto changed_ctl_consumer = leaf_ctl;
    changed_ctl_consumer.shards[0]
        .consumer_product.batch.columns[
            rc::kRCStage3EpisodeTileBridgeExport].root = H(0xd3);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeTileStreamLeafCtl(
            statement, *manifest, stream,
            changed_ctl_consumer, &why));

    auto changed_ctl_transcript = leaf_ctl;
    changed_ctl_transcript.shards[0]
        .pins[0].trace_commitment = H(0xd4);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeTileStreamLeafCtl(
            statement, *manifest, stream,
            changed_ctl_transcript, &why));

    auto changed = extract;
    ++changed.tiles[0].input[0];
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeExtractProduct(
        statement, *manifest, changed, stream, &why));
}

BOOST_AUTO_TEST_SUITE_END()
