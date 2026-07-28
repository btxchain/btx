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

CBlockHeader MiningHeader(uint64_t nonce)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = 0x51;
        header.hashMerkleRoot.data()[i] = 0xa3;
        header.seed_a.data()[i] = 0x11;
        header.seed_b.data()[i] = 0x22;
    }
    return header;
}

struct CaptureTerminalProxy final
    : rc::RCEpisodeProofWitnessSink {
    explicit CaptureTerminalProxy(
        rc::RCStage3EpisodeWitnessCapture& capture_in)
        : capture(capture_in)
    {
    }

    rc::RCStage3EpisodeWitnessCapture& capture;
    bool omit_digest{false};
    bool substitute_first_root{false};
    bool reorder_first_root{false};

    void OnPhase1Operands(
        const rc::RCPhase1OperandsWitnessView& view) override
    {
        capture.OnPhase1Operands(view);
    }
    void OnPhase1QKtTile(
        const rc::RCPhase1QKtTileWitnessView& view) override
    {
        capture.OnPhase1QKtTile(view);
    }
    void OnPhase1SVRow(
        const rc::RCPhase1SVRowWitnessView& view) override
    {
        capture.OnPhase1SVRow(view);
    }
    void OnFfnGemm(
        const rc::RCFfnGemmWitnessView& view) override
    {
        capture.OnFfnGemm(view);
    }
    void OnFfnExtract(
        const rc::RCFfnExtractWitnessView& view) override
    {
        capture.OnFfnExtract(view);
    }
    void OnRoundRoot(
        uint32_t round_ordinal,
        const uint256& round_root) override
    {
        if (reorder_first_root &&
            round_ordinal == 0) {
            capture.OnRoundRoot(
                round_ordinal + 1U,
                round_root);
            return;
        }
        if (!substitute_first_root ||
            round_ordinal != 0) {
            capture.OnRoundRoot(
                round_ordinal, round_root);
            return;
        }
        uint256 substituted = round_root;
        substituted.begin()[0] ^= 1U;
        capture.OnRoundRoot(
            round_ordinal, substituted);
    }
    void OnEpisodeDigest(
        const uint256& episode_digest) override
    {
        if (!omit_digest) {
            capture.OnEpisodeDigest(
                episode_digest);
        }
    }
};

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
        layer.gemm_y.assign(
            uint64_t{spec.m} * spec.n, 0);
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
                    layer.gemm_y[cell] = sum;
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
    real_miner_callbacks_materialize_complete_canonical_product_witness)
{
    const auto params = rc::MakeToyRCEpisodeParams();
    const auto header = MiningHeader(42);
    rc::RCStage3EpisodeWitnessCapture capture(params);
    std::vector<rc::RCRoundTranscript> rounds;
    const uint256 digest =
        rc::MineRCEpisodeWithProofWitness(
            header, params, 0, capture, &rounds);
    BOOST_REQUIRE(!digest.IsNull());
    std::string why;
    BOOST_REQUIRE_MESSAGE(capture.Complete(&why), why);
    BOOST_CHECK(capture.EpisodeDigest() == digest);
    BOOST_REQUIRE_EQUAL(
        capture.RoundRoots().size(), rounds.size());
    for (uint32_t round = 0;
         round < rounds.size(); ++round) {
        BOOST_CHECK(
            capture.RoundRoots()[round] ==
            rounds[round].round_root);
        std::vector<int8_t> captured_stream;
        BOOST_REQUIRE_MESSAGE(
            capture.BuildRoundStream(
                round, captured_stream, &why),
            why);
        BOOST_CHECK(captured_stream ==
                    rounds[round].stream);
        BOOST_CHECK(
            rc::BuildTileTreeRoot(
                captured_stream,
                params.T_leaf) ==
            capture.RoundRoots()[round]);
    }

    const auto layout = rc::RCGkrTraceLayout(params);
    BOOST_REQUIRE_EQUAL(
        capture.LayerWitnesses().size(),
        layout.layers.size());
    uint64_t expected_tiles = 0;
    for (uint32_t ordinal = 0;
         ordinal < layout.layers.size(); ++ordinal) {
        const auto& spec = layout.layers[ordinal];
        const auto& layer =
            capture.LayerWitnesses()[ordinal];
        BOOST_CHECK_EQUAL(
            layer.operand_a.size(),
            uint64_t{spec.m} * spec.k);
        BOOST_CHECK_EQUAL(
            layer.operand_b.size(),
            uint64_t{spec.k} * spec.n);
        BOOST_CHECK_EQUAL(
            layer.gemm_y.size(),
            uint64_t{spec.m} * spec.n);
        expected_tiles +=
            uint64_t{spec.m} *
            (spec.n / rc::kRCMxBlockLen);
    }
    BOOST_CHECK_EQUAL(
        capture.ExtractInputs().size(), expected_tiles);

    auto bindings = Bindings(params);
    BOOST_REQUIRE_EQUAL(
        bindings.size(), capture.ExtractPrfs().size());
    for (uint32_t ordinal = 0;
         ordinal < bindings.size(); ++ordinal) {
        bindings[ordinal].extract_prf =
            capture.ExtractPrfs()[ordinal];
    }
    const auto statement = Statement();
    const auto manifest =
        rc::BuildRCStage3GemmExtractManifest(
            params,
            rc::RCStage3EpisodeStatementCommitment(statement),
            bindings, &why);
    BOOST_REQUIRE_MESSAGE(manifest.has_value(), why);
    BOOST_CHECK_MESSAGE(
        capture.ValidateManifest(*manifest, &why), why);

    rc::RCStage3EpisodeWitnessCapture reordered(params);
    std::array<int8_t, rc::kRCMxBlockLen> zeros8{};
    std::array<int64_t, rc::kRCMxBlockLen> zeros64{};
    reordered.OnPhase1QKtTile({
        .round_ordinal = 0,
        .query_row = 0,
        .context_begin = 0,
        .tile_len = rc::kRCMxBlockLen,
        .contraction_size = params.d_head,
        .operand_a = zeros8.data(),
        .operand_b = zeros8.data(),
        .gemm_y = zeros64.data(),
        .extract_output = zeros8.data(),
        .prf_key = H(0x91),
    });
    BOOST_CHECK(!reordered.Complete(&why));
    auto rejected_manifest = *manifest;
    rc::RCStage3EpisodeExtractProduct rejected_extract;
    rc::RCStage3EpisodeTileStreamProduct rejected_stream;
    rc::RCStage3EpisodeGemmProduct rejected_gemm;
    BOOST_CHECK(
        !rc::ProveRCStage3EpisodeProductsFromCapture(
            statement, rejected_manifest, reordered,
            rejected_extract, rejected_stream,
            rejected_gemm, &why));

    rc::RCStage3EpisodeWitnessStoreClearForTest();
    const uint256 winner_hash = H(0xd1);
    auto stored = std::make_shared<
        const rc::RCStage3EpisodeWitnessCapture>(
            capture);
    BOOST_REQUIRE_MESSAGE(
        rc::RCStage3EpisodeWitnessStorePut(
            winner_hash, stored, &why),
        why);
    BOOST_CHECK(
        rc::RCStage3EpisodeWitnessStoreGet(
            winner_hash) == stored);
    BOOST_CHECK(
        rc::RCStage3EpisodeWitnessStoreGet(
            H(0xd2)) == nullptr);
    rc::RCStage3EpisodeWitnessStoreErase(H(0xd2));
    BOOST_CHECK(
        rc::RCStage3EpisodeWitnessStoreGet(
            winner_hash) == stored);
    rc::RCStage3EpisodeWitnessStoreErase(
        winner_hash);
    BOOST_CHECK(
        rc::RCStage3EpisodeWitnessStoreGet(
            winner_hash) == nullptr);

    // Terminal events are part of the capture schedule, not optional host
    // metadata. Omitting the final digest or substituting a solver-native
    // round root leaves an otherwise complete A/B/Y/Extract capture unusable.
    rc::RCStage3EpisodeWitnessCapture omitted(params);
    CaptureTerminalProxy omit_proxy(omitted);
    omit_proxy.omit_digest = true;
    BOOST_REQUIRE(
        !rc::MineRCEpisodeWithProofWitness(
             header, params, 0, omit_proxy)
             .IsNull());
    BOOST_CHECK(!omitted.Complete(&why));
    BOOST_CHECK(
        why.find("capture_incomplete_episode_terminal") !=
        std::string::npos);

    rc::RCStage3EpisodeWitnessCapture substituted(params);
    CaptureTerminalProxy substitute_proxy(substituted);
    substitute_proxy.substitute_first_root = true;
    BOOST_REQUIRE(
        !rc::MineRCEpisodeWithProofWitness(
             header, params, 0, substitute_proxy)
             .IsNull());
    BOOST_CHECK(!substituted.Complete(&why));
    BOOST_CHECK(
        why.find("capture_episode_digest_order") !=
        std::string::npos);

    rc::RCStage3EpisodeWitnessCapture reordered_terminal(
        params);
    CaptureTerminalProxy reorder_proxy(
        reordered_terminal);
    reorder_proxy.reorder_first_root = true;
    BOOST_REQUIRE(
        !rc::MineRCEpisodeWithProofWitness(
             header, params, 0, reorder_proxy)
             .IsNull());
    BOOST_CHECK(
        !reordered_terminal.Complete(&why));
    BOOST_CHECK(
        why.find("capture_round_root_order") !=
        std::string::npos);
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
    auto forged_witnesses = witnesses;
    ++forged_witnesses.front().gemm_y.front();
    rc::RCStage3EpisodeGemmProduct forged;
    BOOST_CHECK(
        !rc::ProveRCStage3EpisodeGemmProduct(
            statement, *manifest, forged_witnesses,
            extract, stream, forged, &why));
    BOOST_CHECK_NE(
        why.find("prove_extract_input_equality"),
        std::string::npos);
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
