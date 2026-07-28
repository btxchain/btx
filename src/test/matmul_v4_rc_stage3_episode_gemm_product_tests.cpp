// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_episode_gemm_openings_proof_owned.h>
#include <matmul/matmul_v4_rc_stage3_episode_gemm_product.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <matmul/matmul_v4_rc_gkr_air.h>

#include <array>
#include <cstdlib>
#include <map>

namespace {

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace gf = rc::gkr_field;
namespace ga = rc::gkr_air;
namespace owned =
    rc::episode_gemm_openings_proof_owned;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{
        Span<const unsigned char>{bytes.data(), bytes.size()}};
}

struct HonestDot {
    rc::RCStage3EpisodeGemmDotPin pin;
    std::vector<std::vector<gf::Fp3>> columns;
};

HonestDot BuildHonestDot()
{
    constexpr uint32_t K = 32;
    constexpr uint32_t N = K * rc::kRCMxBlockLen;
    HonestDot out;
    out.columns.assign(
        rc::kRCStage3GemmDotColumns,
        std::vector<gf::Fp3>(N, gf::Fp3::Zero()));
    for (uint32_t lane = 0; lane < rc::kRCMxBlockLen;
         ++lane) {
        for (uint32_t contraction = 0;
             contraction < K; ++contraction) {
            const uint32_t row = lane * K + contraction;
            out.columns[rc::kRCStage3GemmDotActive][row] =
                gf::Fp3::One();
            out.columns[rc::kRCStage3GemmDotStart][row] =
                gf::Fp3::FromFp(
                    gf::FromU64(contraction == 0));
            out.columns[rc::kRCStage3GemmDotEnd][row] =
                gf::Fp3::FromFp(
                    gf::FromU64(contraction + 1 == K));
            out.columns[rc::kRCStage3GemmDotA][row] =
                gf::Fp3::One();
            out.columns[rc::kRCStage3GemmDotB][row] =
                gf::Fp3::One();
            out.columns[rc::kRCStage3GemmDotProduct][row] =
                gf::Fp3::One();
            out.columns[
                rc::kRCStage3GemmDotAccumulatorBefore][row] =
                gf::Fp3::FromFp(gf::FromU64(contraction));
            out.columns[
                rc::kRCStage3GemmDotAccumulatorAfter][row] =
                gf::Fp3::FromFp(
                    gf::FromU64(contraction + 1));
            if (contraction + 1 == K) {
                out.columns[rc::kRCStage3GemmDotY][row] =
                    gf::Fp3::FromFp(gf::FromU64(K));
                out.columns[
                    rc::kRCStage3GemmDotResidual][row] =
                    gf::Fp3::FromFp(gf::FromU64(2));
                out.columns[
                    rc::kRCStage3GemmDotExtractInput][row] =
                    gf::Fp3::FromFp(gf::FromU64(K + 2));
            }
        }
    }

    out.pin.statement_commitment = H(0x11);
    out.pin.manifest_commitment = H(0x22);
    out.pin.layer_ordinal = 3;
    out.pin.layer_tile_index = 5;
    out.pin.contraction_size = K;
    out.pin.logical_rows = N;
    out.pin.n_rows = N;
    out.pin.n_coeffs = N;
    for (uint32_t column = 0;
         column < out.columns.size(); ++column) {
        out.pin.column_roots.push_back({
            column,
            aq::AirCommittedValuesRoot<gf::Fp3>(
                out.columns[column], out.pin.n_coeffs)});
    }
    out.pin.pin_commitment =
        rc::ComputeRCStage3EpisodeGemmDotPinCommitment(
            out.pin);
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

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Episode;
    out.public_inputs.height = 151;
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

using RefKey = std::pair<uint32_t, uint32_t>;

RefKey Key(const rc::RCGkrOperandRef& ref)
{
    return {ref.first_column, ref.n_chunks};
}

bool BuildConsistentWitnesses(
    const rc::RCStage3GemmExtractManifest& manifest,
    std::vector<rc::RCStage3EpisodeGemmLayerWitness>& layers,
    std::vector<std::array<int64_t, rc::kRCMxBlockLen>>&
        extract_inputs,
    std::string* why)
{
    const auto fail = [&](const std::string& message) {
        if (why) *why = message;
        return false;
    };
    layers.clear();
    extract_inputs.clear();
    layers.resize(manifest.layers.size());
    std::map<RefKey, std::vector<int8_t>> produced;
    for (uint32_t ordinal = 0;
         ordinal < manifest.layers.size(); ++ordinal) {
        const auto& spec = manifest.layers[ordinal];
        auto& layer = layers[ordinal];
        const auto resolve =
            [&](const rc::RCGkrOperandRef& ref,
                uint64_t count) {
                const auto found = produced.find(Key(ref));
                if (found != produced.end() &&
                    found->second.size() == count) {
                    return found->second;
                }
                std::vector<int8_t> external(count, 0);
                produced[Key(ref)] = external;
                return external;
            };
        layer.operand_a = resolve(
            spec.a, uint64_t{spec.m} * spec.k);
        layer.operand_b = resolve(
            spec.b, uint64_t{spec.k} * spec.n);
        if (spec.residual_first_column >= 0) {
            for (const auto& [ref, values] : produced) {
                if (ref.first ==
                        static_cast<uint32_t>(
                            spec.residual_first_column) &&
                    values.size() ==
                        uint64_t{spec.m} * spec.n) {
                    layer.residual = values;
                    break;
                }
            }
            if (layer.residual.empty()) {
                return fail(
                    "missing residual producer at layer " +
                    std::to_string(ordinal));
            }
        }
        std::vector<int8_t> outputs(
            uint64_t{spec.m} * spec.n);
        const uint32_t blocks_per_row =
            spec.n / rc::kRCMxBlockLen;
        for (uint32_t row = 0; row < spec.m; ++row) {
            for (uint32_t block = 0;
                 block < blocks_per_row; ++block) {
                std::array<int64_t, rc::kRCMxBlockLen> input{};
                for (uint32_t lane = 0;
                     lane < rc::kRCMxBlockLen; ++lane) {
                    const uint32_t column =
                        block * rc::kRCMxBlockLen + lane;
                    int64_t sum = 0;
                    for (uint32_t contraction = 0;
                         contraction < spec.k; ++contraction) {
                        const int64_t a = layer.operand_a[
                            uint64_t{row} * spec.k +
                            contraction];
                        const int64_t b = spec.b.transpose
                            ? layer.operand_b[
                                  uint64_t{column} * spec.k +
                                  contraction]
                            : layer.operand_b[
                                  uint64_t{contraction} * spec.n +
                                  column];
                        sum += a * b;
                    }
                    const uint64_t cell =
                        uint64_t{row} * spec.n + column;
                    input[lane] = sum +
                        (layer.residual.empty()
                             ? 0
                             : layer.residual[cell]);
                }
                const ga::TilePublic tile_public{
                    spec.bindings.extract_prf, row, block};
                const ga::TileWitness tile =
                    ga::TraceTile(tile_public, input);
                if (!ga::ByteExactVsReference(
                        tile_public, input)) {
                    return fail(
                        "Extract reference mismatch at layer " +
                        std::to_string(ordinal) + " tile " +
                        std::to_string(
                            uint64_t{row} * blocks_per_row +
                            block));
                }
                extract_inputs.push_back(input);
                for (uint32_t lane = 0;
                     lane < rc::kRCMxBlockLen; ++lane) {
                    outputs[
                        uint64_t{row} * spec.n +
                        block * rc::kRCMxBlockLen + lane] =
                        tile.out[lane];
                }
            }
        }
        produced[{spec.out_first_column, spec.out_chunks}] =
            std::move(outputs);
    }
    if (extract_inputs.size() != manifest.total_extract_tiles) {
        return fail(
            "tile-count mismatch: got " +
            std::to_string(extract_inputs.size()) +
            ", expected " +
            std::to_string(manifest.total_extract_tiles));
    }
    return true;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_episode_gemm_product_tests)

BOOST_AUTO_TEST_CASE(audit_is_local_and_fail_closed_transitively)
{
    const auto audit =
        rc::CurrentRCStage3EpisodeGemmProductAudit();
    BOOST_CHECK(audit.immutable_full_lambda_schedule);
    BOOST_CHECK(audit.all_operand_openings_bound);
    BOOST_CHECK(audit.every_dot_product_air_executed);
    BOOST_CHECK(audit.complete_signed_arithmetic_identity);
    BOOST_CHECK(audit.y_root_bound);
    BOOST_CHECK(audit.y_residual_to_extract_input_equality);
    BOOST_CHECK(
        audit.internal_extract_and_wiring_producers_linked);
    BOOST_CHECK(audit.endpoints_5_through_8_locally_complete);
    BOOST_CHECK(!audit.external_builder_provenance_complete);
    BOOST_CHECK(!audit.production_streaming_complete);
    BOOST_CHECK(!audit.recursively_consumed);
    BOOST_CHECK(!audit.transitively_complete);
}

BOOST_AUTO_TEST_CASE(
    dot_air_executes_full_signed_sum_and_rejects_opening_and_sum_attacks)
{
    HonestDot fixture = BuildHonestDot();
    BOOST_REQUIRE(!fixture.pin.pin_commitment.IsNull());
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeGemmDotConstraintSystem(
            fixture.pin, cs, &why),
        why);
    const auto proved = aq::AirQuotientProve<gf::Fp3>(
        cs, fixture.columns,
        rc::ComputeRCStage3EpisodeGemmDotSeed(fixture.pin));
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact, proved.note);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeGemmDotProof(
            fixture.pin, proved.proof, &why),
        why);

    auto substituted = fixture.pin;
    substituted.column_roots[
        rc::kRCStage3GemmDotY].root = H(0xf1);
    substituted.pin_commitment =
        rc::ComputeRCStage3EpisodeGemmDotPinCommitment(
            substituted);
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeGemmDotProof(
        substituted, proved.proof, &why));

    auto bad_sum = fixture.columns;
    bad_sum[rc::kRCStage3GemmDotAccumulatorAfter][31] =
        gf::Fp3::FromFp(gf::FromU64(31));
    const auto forged = aq::AirQuotientProve<gf::Fp3>(
        cs, bad_sum,
        rc::ComputeRCStage3EpisodeGemmDotSeed(fixture.pin));
    BOOST_CHECK(!forged.ok || !forged.division_exact);
}

BOOST_AUTO_TEST_CASE(
    receipts_reject_tile_omission_order_and_pin_root_attacks)
{
    const HonestDot honest = BuildHonestDot();
    rc::RCStage3EpisodeGemmLayerProduct layer;
    layer.operand_a.assign(32, 1);
    layer.operand_b.assign(32, 1);
    layer.gemm_y.assign(32, 32);
    for (uint64_t i = 0; i < 2; ++i) {
        rc::RCStage3EpisodeGemmTileProof tile;
        tile.layer_tile_index = i;
        tile.pin = honest.pin;
        tile.pin.layer_tile_index = i;
        tile.pin.pin_commitment =
            rc::ComputeRCStage3EpisodeGemmDotPinCommitment(
                tile.pin);
        layer.tiles.push_back(std::move(tile));
    }
    const uint256 receipt =
        rc::ComputeRCStage3EpisodeGemmLayerReceiptCommitment(
            layer);
    BOOST_REQUIRE(!receipt.IsNull());

    auto omitted = layer;
    omitted.tiles.erase(omitted.tiles.begin());
    BOOST_CHECK(
        rc::ComputeRCStage3EpisodeGemmLayerReceiptCommitment(
            omitted)
            .IsNull());

    auto reordered = layer;
    std::swap(reordered.tiles[0], reordered.tiles[1]);
    BOOST_CHECK(
        rc::ComputeRCStage3EpisodeGemmLayerReceiptCommitment(
            reordered)
            .IsNull());

    auto root_attack = layer;
    root_attack.tiles[0]
        .pin.column_roots[rc::kRCStage3GemmDotA]
        .root = H(0xee);
    BOOST_CHECK(
        rc::ComputeRCStage3EpisodeGemmLayerReceiptCommitment(
            root_attack) != receipt);

    auto opening_attack = layer;
    opening_attack.operand_a[0] = 2;
    BOOST_CHECK(
        rc::ComputeRCStage3EpisodeGemmLayerReceiptCommitment(
            opening_attack) != receipt);
}

BOOST_AUTO_TEST_CASE(
    alg_authority_roots_are_value_derived_and_reject_mutation_transplant)
{
    const auto params = TinyParams();
    std::string why;
    auto manifest = rc::BuildRCStage3GemmExtractManifest(
        params, H(0x91), Bindings(params), &why);
    BOOST_REQUIRE_MESSAGE(manifest.has_value(), why);

    rc::RCStage3EpisodeGemmProduct gemm;
    gemm.layers.resize(manifest->layers.size());
    rc::RCStage3EpisodeExtractProduct extract;
    extract.tiles.resize(manifest->total_extract_tiles);
    for (uint32_t ordinal = 0;
         ordinal < manifest->layers.size(); ++ordinal) {
        const auto& spec = manifest->layers[ordinal];
        auto& layer = gemm.layers[ordinal];
        layer.layer_ordinal = ordinal;
        layer.operand_a.assign(
            uint64_t{spec.m} * spec.k,
            static_cast<int8_t>(1 + ordinal % 7));
        layer.operand_b.assign(
            uint64_t{spec.k} * spec.n,
            static_cast<int8_t>(-1 -
                static_cast<int32_t>(ordinal % 7)));
        layer.gemm_y.assign(
            uint64_t{spec.m} * spec.n,
            static_cast<int64_t>(17 + ordinal));
        for (uint64_t tile = 0;
             tile < spec.extract_tile_count; ++tile) {
            auto& input =
                extract.tiles[
                    spec.extract_tile_begin + tile].input;
            for (uint32_t lane = 0;
                 lane < input.size(); ++lane) {
                input[lane] =
                    static_cast<int64_t>(
                        1000U * ordinal +
                        32U * tile + lane);
            }
        }
    }

    BOOST_REQUIRE_MESSAGE(
        rc::BindRCStage3EpisodeGemmAlgAuthorityRoots(
            *manifest, gemm, extract, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::ValidateRCStage3EpisodeGemmAlgAuthorityRoots(
            *manifest, gemm, extract, &why),
        why);
    for (const auto& layer : manifest->layers) {
        BOOST_CHECK(
            !layer.bindings.operand_a_root_alg.IsNull());
        BOOST_CHECK(
            !layer.bindings.operand_b_root_alg.IsNull());
        BOOST_CHECK(
            !layer.bindings.gemm_y_root_alg.IsNull());
        BOOST_CHECK(
            !layer.bindings.extract_input_root_alg.IsNull());
    }

    auto root_mutation = *manifest;
    root_mutation.layers[0]
        .bindings.gemm_y_root_alg = H(0xe1);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeGemmAlgAuthorityRoots(
            root_mutation, gemm, extract, &why));

    BOOST_REQUIRE_GT(manifest->layers.size(), 1U);
    auto root_transplant = *manifest;
    std::swap(
        root_transplant.layers[0]
            .bindings.operand_a_root_alg,
        root_transplant.layers[1]
            .bindings.operand_a_root_alg);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeGemmAlgAuthorityRoots(
            root_transplant, gemm, extract, &why));

    auto producer_mutation = gemm;
    ++producer_mutation.layers[0].operand_b[0];
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeGemmAlgAuthorityRoots(
            *manifest, producer_mutation, extract, &why));

    auto extract_mutation = extract;
    ++extract_mutation.tiles[0].input[0];
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeGemmAlgAuthorityRoots(
            *manifest, gemm, extract_mutation, &why));
}

BOOST_AUTO_TEST_CASE(
    honest_whole_episode_gemm_extract_stream_product_executes)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_EPISODE_GEMM_PRODUCT_PROVE") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_EPISODE_GEMM_PRODUCT_PROVE=1 "
            "for the complete GEMM+Extract+stream positive product");
        return;
    }
    const auto statement = Statement();
    const auto params = TinyParams();
    std::string why;
    auto manifest = rc::BuildRCStage3GemmExtractManifest(
        params, rc::RCStage3EpisodeStatementCommitment(statement),
        Bindings(params), &why);
    BOOST_REQUIRE_MESSAGE(manifest.has_value(), why);
    std::vector<rc::RCStage3EpisodeGemmLayerWitness> witnesses;
    std::vector<std::array<int64_t, rc::kRCMxBlockLen>>
        extract_inputs;
    BOOST_REQUIRE_MESSAGE(
        BuildConsistentWitnesses(
            *manifest, witnesses, extract_inputs, &why),
        why);
    rc::RCStage3EpisodeExtractProduct extract;
    rc::RCStage3EpisodeTileStreamProduct stream;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeExtractAndTileStreamProducts(
            statement, *manifest, extract_inputs,
            extract, stream, &why),
        why);
    rc::RCStage3EpisodeGemmProduct gemm;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeGemmProduct(
            statement, *manifest, witnesses,
            extract, stream, gemm, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeGemmProduct(
            statement, *manifest, gemm, extract, &why),
        why);
    for (const auto& layer : manifest->layers) {
        BOOST_REQUIRE(
            !layer.bindings.operand_a_root_alg.IsNull());
        BOOST_REQUIRE(
            !layer.bindings.operand_b_root_alg.IsNull());
        BOOST_REQUIRE(
            !layer.bindings.gemm_y_root_alg.IsNull());
        BOOST_REQUIRE(
            !layer.bindings.extract_input_root_alg.IsNull());
    }

    owned::StatementV1 openings_statement;
    BOOST_REQUIRE_MESSAGE(
        owned::BuildStatementFromOwningGemmProductV1(
            statement, *manifest, gemm, extract,
            openings_statement, &why),
        why);
    std::array<
        std::vector<gf::Fp3>, owned::kEndpointCountV1>
        opening_values;
    for (const auto& layer : gemm.layers) {
        for (const int8_t value : layer.operand_a) {
            opening_values[0].push_back(
                gf::Fp3::FromFp(gf::FromSigned(value)));
        }
        for (const int8_t value : layer.operand_b) {
            opening_values[1].push_back(
                gf::Fp3::FromFp(gf::FromSigned(value)));
        }
        for (const int64_t value : layer.gemm_y) {
            opening_values[2].push_back(
                gf::Fp3::FromFp(gf::FromSigned(value)));
        }
    }
    owned::ProofV1 openings_proof;
    BOOST_REQUIRE_MESSAGE(
        owned::ProveV1(
            openings_statement, opening_values,
            openings_proof, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        owned::VerifyWithOwningGemmProductV1(
            statement, *manifest, gemm, extract,
            openings_statement, openings_proof, &why),
        why);
    const auto openings_audit =
        owned::AssessWithOwningGemmProductV1(
            statement, *manifest, gemm, extract,
            openings_statement, openings_proof);
    BOOST_REQUIRE_MESSAGE(
        openings_audit.valid, openings_audit.note);
    BOOST_CHECK(
        openings_audit.owning_manifest_authority_roots_bound);
    BOOST_CHECK(
        openings_audit.owning_relation_product_verified);
    BOOST_CHECK(
        openings_audit.owning_producer_roots_bound);
    BOOST_CHECK(openings_audit.source_bridge_host_linear);
    BOOST_CHECK(
        !openings_audit.source_bridge_normalized_recursive);
    BOOST_CHECK(
        (openings_audit.residual_obligations &
         rc::universal_topology::
             ProductionResidualSourceRootProvenance) != 0);

    auto opening_query_attack = openings_proof;
    auto& opening_child =
        opening_query_attack.endpoint_bundles[0]
            .shards[0].proof.quotient;
    BOOST_REQUIRE(!opening_child.batch.queries.empty());
    BOOST_REQUIRE(
        !opening_child.batch.queries[0].columns.empty());
    opening_child.batch.queries[0].columns[0].value =
        gf::Add(
            opening_child.batch.queries[0]
                .columns[0].value,
            gf::Fp3::One());
    opening_query_attack.endpoint_bundles[0]
        .bundle_commitment =
        rc::ComputeRCStage3EpisodeSemanticMemoryBundleCommitment(
            opening_query_attack.endpoint_bundles[0]);
    opening_query_attack.ordered_proof_set_commitment =
        owned::ComputeOrderedProofSetCommitmentV1(
            opening_query_attack);
    BOOST_CHECK(
        !owned::VerifyWithOwningGemmProductV1(
            statement, *manifest, gemm, extract,
            openings_statement, opening_query_attack,
            &why));

    auto changed = gemm;
    ++changed.layers[0].gemm_y[0];
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeGemmProduct(
        statement, *manifest, changed, extract, &why));
    auto changed_authority = *manifest;
    changed_authority.layers[0]
        .bindings.gemm_y_root_alg = H(0xe2);
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeGemmProduct(
        statement, changed_authority, gemm, extract, &why));
    BOOST_REQUIRE_GT(manifest->layers.size(), 1U);
    auto transplanted_authority = *manifest;
    std::swap(
        transplanted_authority.layers[0]
            .bindings.operand_a_root_alg,
        transplanted_authority.layers[1]
            .bindings.operand_a_root_alg);
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeGemmProduct(
        statement, transplanted_authority, gemm, extract,
        &why));
}

BOOST_AUTO_TEST_SUITE_END()
