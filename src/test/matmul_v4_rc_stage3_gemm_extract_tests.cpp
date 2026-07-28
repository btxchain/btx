// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_gemm_extract_tests,
                         BasicTestingSetup)

namespace {

uint256 Filled(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

uint32_t NextPowerOfTwo(uint64_t value)
{
    uint32_t out = 1;
    while (out < value) out <<= 1;
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

std::vector<rc::RCStage3GemmExtractLayerBindings>
Bindings(const rc::RCEpisodeParams& params)
{
    const auto layout = rc::RCGkrTraceLayout(params);
    std::vector<rc::RCStage3GemmExtractLayerBindings> out(
        layout.layers.size());
    uint32_t counter = 1;
    auto next_root = [&] {
        const auto byte =
            static_cast<unsigned char>(1 + (counter++ % 254));
        return Filled(byte);
    };
    for (auto& binding : out) {
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
    }
    return out;
}

rc::RCStage3GemmExtractManifest Manifest()
{
    std::string why;
    const auto params = SmallParams();
    const auto built = rc::BuildRCStage3GemmExtractManifest(
        params, Filled(0xa1), Bindings(params), &why);
    BOOST_REQUIRE_MESSAGE(built.has_value(), why);
    return *built;
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof statement;
    statement.statement = rc::RCStage3StatementKind::Episode;
    statement.public_inputs.height = 44;
    statement.public_inputs.episode_profile = 2;
    statement.public_inputs.header_commitment = Filled(0x81);
    statement.public_inputs.params_commitment = Filled(0x82);
    statement.public_inputs.target = Filled(0x83);
    statement.public_inputs.sigma = Filled(0x84);
    statement.public_inputs.episode_digest = Filled(0x85);
    statement.public_inputs.final_digest = Filled(0x85);
    return statement;
}

rc::RCStage3SignedRangePin PinnedRangePin(
    const rc::RCStage3GemmExtractManifest& manifest,
    uint32_t layer)
{
    std::string why;
    auto pin = rc::MakeRCStage3SignedRangePin(
        manifest, layer, 0, &why);
    BOOST_REQUIRE_MESSAGE(pin.has_value(), why);
    for (uint32_t i = 0; i < pin->column_roots.size(); ++i) {
        pin->column_roots[i].root =
            Filled(static_cast<unsigned char>(1 + (i % 250)));
    }
    return *pin;
}

rc::RCStage3SignedRangeCtlShard CtlShard(
    const rc::RCStage3GemmExtractManifest& manifest,
    uint32_t layer)
{
    rc::RCStage3SignedRangeCtlShard out;
    out.pin = PinnedRangePin(manifest, layer);
    auto& binding = out.binding;
    binding.extract_input_shard_root =
        Filled(static_cast<unsigned char>(0x40 + layer));
    binding.extract_input_opening_commitment =
        Filled(static_cast<unsigned char>(0x60 + layer));

    const auto ctl_manifest =
        rc::BuildRCStage3SignedRangeCtlManifest(
            manifest, out.pin, binding);
    BOOST_REQUIRE_EQUAL(ctl_manifest.participants.size(), 2U);
    auto fill_prechallenge = [&](rc::RCStage3CtlChildPin& child,
                                 size_t participant,
                                 const uint256& trace) {
        const auto& spec = ctl_manifest.participants[participant];
        child.role = spec.role;
        child.bus_id = ctl_manifest.bus_id;
        child.event_count = spec.event_count;
        child.send_count = spec.send_count;
        child.receive_count = spec.receive_count;
        child.schedule_commitment = spec.schedule_commitment;
        child.trace_commitment = trace;
    };
    fill_prechallenge(
        binding.range_child, 0,
        rc::ComputeRCStage3SignedRangeCtlTraceCommitment(out.pin));
    fill_prechallenge(
        binding.extract_child, 1,
        rc::ComputeRCStage3ExtractCtlTraceCommitment(
            manifest, out.pin, binding));

    rc::RCStage3CtlChallenges challenges;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::DeriveRCStage3CtlChallenges(
            ctl_manifest,
            {binding.range_child, binding.extract_child},
            challenges, &why), why);
    const uint256 challenge_commitment =
        rc::CommitRCStage3CtlChallenges(challenges);
    binding.range_child.challenge_commitment = challenge_commitment;
    binding.extract_child.challenge_commitment = challenge_commitment;
    binding.range_child.auxiliary_commitment =
        Filled(static_cast<unsigned char>(0x80 + layer));
    binding.extract_child.auxiliary_commitment =
        Filled(static_cast<unsigned char>(0xa0 + layer));

    std::vector<gf::Fp3> values(out.pin.logical_rows);
    for (uint32_t i = 0; i < values.size(); ++i) {
        values[i] = gf::FromU64_3(i + 1);
    }
    const auto producer = rc::BuildRCStage3CtlWitness(
        rc::BuildRCStage3SignedRangeCtlSchedule(
            manifest, out.pin, true),
        values, challenges);
    const auto consumer = rc::BuildRCStage3CtlWitness(
        rc::BuildRCStage3SignedRangeCtlSchedule(
            manifest, out.pin, false),
        values, challenges);
    BOOST_REQUIRE_MESSAGE(producer.ok, producer.note);
    BOOST_REQUIRE_MESSAGE(consumer.ok, consumer.note);
    binding.range_child.terminal = producer.terminal;
    binding.extract_child.terminal = consumer.terminal;
    return out;
}

rc::RCStage3SignedRangeExecutedCtlShardProof ExecutedCtlShard(
    const rc::RCStage3GemmExtractManifest& manifest,
    uint32_t layer,
    const rc::RCStage3ExtractInputShardOpening* opening = nullptr)
{
    rc::RCStage3SignedRangeExecutedCtlShardProof out;
    std::string why;
    const auto bare_pin =
        rc::MakeRCStage3SignedRangePin(manifest, layer, 0, &why);
    BOOST_REQUIRE_MESSAGE(bare_pin.has_value(), why);
    out.pin = *bare_pin;

    std::vector<int64_t> signed_values(out.pin.logical_rows);
    for (uint32_t i = 0; i < signed_values.size(); ++i) {
        const int64_t magnitude =
            static_cast<int64_t>(i % (out.pin.max_abs + 1));
        signed_values[i] = i % 3 == 0 ? -magnitude : magnitude;
    }
    std::vector<std::vector<gf::Fp3>> range_columns;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3SignedRangeColumns(
            out.pin, signed_values, range_columns, &why), why);
    const uint32_t aligned_coeffs =
        NextPowerOfTwo(3 * static_cast<uint64_t>(out.pin.n_rows) - 3);
    for (uint32_t column = 0; column < range_columns.size(); ++column) {
        out.pin.column_roots[column].root =
            aq::AirCommittedValuesRoot<gf::Fp3>(
                range_columns[column], aligned_coeffs);
    }

    aq::AirConstraintSystem<gf::Fp3> range_cs;
    BOOST_REQUIRE_MESSAGE(
        rc::ResolveRCStage3SignedRangeCtlAlignedConstraintSystem(
            manifest, out.pin, range_cs, &why), why);
    const auto range_result =
        aq::AirQuotientProve<gf::Fp3>(
            range_cs, range_columns,
            rc::ComputeRCStage3SignedRangeSeed(out.pin));
    BOOST_REQUIRE_MESSAGE(range_result.ok, range_result.note);
    BOOST_REQUIRE(range_result.division_exact);
    out.range_proof = range_result.proof;

    out.binding.extract_input_shard_root =
        out.pin.column_roots[rc::kRCStage3RangeValue].root;
    out.binding.extract_input_opening_commitment = opening == nullptr
        ? Filled(static_cast<unsigned char>(0xd0 + layer))
        : rc::ComputeRCStage3ExtractInputShardOpeningCommitment(
              manifest, out.pin, *opening);
    BOOST_REQUIRE(!out.binding.extract_input_opening_commitment.IsNull());
    rc::RCStage3SignedRangeCtlBinding manifest_binding;
    manifest_binding.extract_input_shard_root =
        out.binding.extract_input_shard_root;
    manifest_binding.extract_input_opening_commitment =
        out.binding.extract_input_opening_commitment;
    const rc::RCStage3CtlManifest ctl_manifest =
        rc::BuildRCStage3SignedRangeCtlManifest(
            manifest, out.pin, manifest_binding);
    BOOST_REQUIRE_EQUAL(ctl_manifest.participants.size(), 2U);
    const std::vector<rc::RCStage3CtlSchedule> schedules{
        rc::BuildRCStage3SignedRangeCtlSchedule(
            manifest, out.pin, true),
        rc::BuildRCStage3SignedRangeCtlSchedule(
            manifest, out.pin, false),
    };
    std::vector<gf::Fp3> values(
        range_columns[rc::kRCStage3RangeValue].begin(),
        range_columns[rc::kRCStage3RangeValue].begin() +
            out.pin.logical_rows);

    std::vector<rc::RCStage3CtlChildPin*> children{
        &out.binding.range_child,
        &out.binding.extract_child,
    };
    for (size_t i = 0; i < children.size(); ++i) {
        const auto& participant = ctl_manifest.participants[i];
        auto& child = *children[i];
        child.role = participant.role;
        child.bus_id = ctl_manifest.bus_id;
        child.event_count = participant.event_count;
        child.send_count = participant.send_count;
        child.receive_count = participant.receive_count;
        child.schedule_commitment =
            participant.schedule_commitment;
        child.trace_commitment =
            rc::ComputeRCStage3CtlPrechallengeTraceCommitment(
                schedules[i], values);
        BOOST_REQUIRE(!child.trace_commitment.IsNull());
    }

    rc::RCStage3CtlChallenges challenges;
    BOOST_REQUIRE_MESSAGE(
        rc::DeriveRCStage3CtlChallenges(
            ctl_manifest,
            {out.binding.range_child, out.binding.extract_child},
            challenges, &why), why);
    const uint256 challenge_commitment =
        rc::CommitRCStage3CtlChallenges(challenges);
    std::array<rc::RCStage3CtlAirProof*, 2> proofs{
        &out.range_ctl_proof, &out.extract_ctl_proof};
    for (size_t i = 0; i < children.size(); ++i) {
        auto& child = *children[i];
        const rc::RCStage3CtlWitness witness =
            rc::BuildRCStage3CtlWitness(
                schedules[i], values, challenges);
        BOOST_REQUIRE_MESSAGE(witness.ok, witness.note);
        child.terminal = witness.terminal;
        child.challenge_commitment = challenge_commitment;
        const uint256 seed =
            rc::ComputeRCStage3CtlAirSeed(ctl_manifest, child);
        BOOST_REQUIRE(!seed.IsNull());
        const auto cs = rc::BuildRCStage3CtlConstraintSystem(
            {schedules[i], challenges, witness.terminal});
        const auto result =
            aq::AirQuotientProve<gf::Fp3>(
                cs, witness.columns, seed);
        BOOST_REQUIRE_MESSAGE(result.ok, result.note);
        BOOST_REQUIRE(result.division_exact);
        *proofs[i] = result.proof;
        child.auxiliary_commitment =
            rc::ComputeRCStage3CtlAuxiliaryCommitment(*proofs[i]);
        BOOST_REQUIRE(!child.auxiliary_commitment.IsNull());
    }
    return out;
}

struct SignedRangeDualCtlDirectAliasShard {
    rc::RCStage3SignedRangePin pin;
    rc::RCStage3SignedRangeExecutedCtlBinding binding;
    rc::RCStage3SignedRangeDualCtlDirectAliasLayout layout;
    aq::AirConstraintSystem<gf::Fp3> constraint_system;
    std::vector<std::vector<gf::Fp3>> columns;
    uint256 seed{};
    aq::AirQuotientProof<gf::Fp3> proof;
};

SignedRangeDualCtlDirectAliasShard DualCtlDirectAliasShard(
    const rc::RCStage3GemmExtractManifest& manifest,
    uint32_t layer)
{
    SignedRangeDualCtlDirectAliasShard out;
    std::string why;
    const auto bare_pin =
        rc::MakeRCStage3SignedRangePin(manifest, layer, 0, &why);
    BOOST_REQUIRE_MESSAGE(bare_pin.has_value(), why);
    out.pin = *bare_pin;

    std::vector<int64_t> signed_values(out.pin.logical_rows);
    for (uint32_t row = 0; row < signed_values.size(); ++row) {
        const int64_t magnitude =
            static_cast<int64_t>(row % (out.pin.max_abs + 1));
        signed_values[row] =
            row % 3 == 0 ? -magnitude : magnitude;
    }
    std::vector<std::vector<gf::Fp3>> range_columns;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3SignedRangeColumns(
            out.pin, signed_values, range_columns, &why),
        why);
    const uint32_t aligned_coeffs =
        NextPowerOfTwo(
            3 * static_cast<uint64_t>(out.pin.n_rows) - 3);
    for (uint32_t column = 0;
         column < range_columns.size(); ++column) {
        out.pin.column_roots[column].root =
            aq::AirCommittedValuesRoot<gf::Fp3>(
                range_columns[column], aligned_coeffs);
    }

    out.binding.extract_input_shard_root =
        out.pin.column_roots[rc::kRCStage3RangeValue].root;
    out.binding.extract_input_opening_commitment =
        Filled(static_cast<unsigned char>(0xd0 + layer));
    rc::RCStage3SignedRangeCtlBinding manifest_binding;
    manifest_binding.extract_input_shard_root =
        out.binding.extract_input_shard_root;
    manifest_binding.extract_input_opening_commitment =
        out.binding.extract_input_opening_commitment;
    const rc::RCStage3CtlManifest ctl_manifest =
        rc::BuildRCStage3SignedRangeCtlManifest(
            manifest, out.pin, manifest_binding);
    BOOST_REQUIRE_EQUAL(ctl_manifest.participants.size(), 2U);
    const std::array<rc::RCStage3CtlSchedule, 2> schedules{
        rc::BuildRCStage3SignedRangeCtlSchedule(
            manifest, out.pin, true),
        rc::BuildRCStage3SignedRangeCtlSchedule(
            manifest, out.pin, false),
    };
    std::vector<gf::Fp3> values(
        range_columns[rc::kRCStage3RangeValue].begin(),
        range_columns[rc::kRCStage3RangeValue].begin() +
            out.pin.logical_rows);
    std::array<rc::RCStage3CtlChildPin*, 2> children{
        &out.binding.range_child,
        &out.binding.extract_child,
    };
    for (size_t i = 0; i < children.size(); ++i) {
        auto& child = *children[i];
        const auto& participant = ctl_manifest.participants[i];
        child.role = participant.role;
        child.bus_id = ctl_manifest.bus_id;
        child.event_count = participant.event_count;
        child.send_count = participant.send_count;
        child.receive_count = participant.receive_count;
        child.schedule_commitment =
            participant.schedule_commitment;
        child.trace_commitment =
            rc::ComputeRCStage3CtlPrechallengeTraceCommitment(
                schedules[i], values);
        BOOST_REQUIRE(!child.trace_commitment.IsNull());
    }

    rc::RCStage3CtlChallenges challenges;
    BOOST_REQUIRE_MESSAGE(
        rc::DeriveRCStage3CtlChallenges(
            ctl_manifest,
            {out.binding.range_child,
             out.binding.extract_child},
            challenges, &why),
        why);
    const uint256 challenge_commitment =
        rc::CommitRCStage3CtlChallenges(challenges);
    const rc::RCStage3CtlWitness producer =
        rc::BuildRCStage3CtlWitness(
            schedules[0], values, challenges);
    const rc::RCStage3CtlWitness consumer =
        rc::BuildRCStage3CtlWitness(
            schedules[1], values, challenges);
    BOOST_REQUIRE_MESSAGE(producer.ok, producer.note);
    BOOST_REQUIRE_MESSAGE(consumer.ok, consumer.note);
    out.binding.range_child.terminal = producer.terminal;
    out.binding.extract_child.terminal = consumer.terminal;
    out.binding.range_child.challenge_commitment =
        challenge_commitment;
    out.binding.extract_child.challenge_commitment =
        challenge_commitment;

    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3SignedRangeDualCtlDirectAliasConstraintSystem(
            manifest, out.pin, out.binding,
            out.constraint_system, &out.layout, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3SignedRangeDualCtlDirectAliasWitness(
            out.layout, range_columns, producer, consumer,
            out.columns, &why),
        why);
    out.seed =
        rc::ComputeRCStage3SignedRangeDualCtlDirectAliasSeed(
            manifest, out.pin, out.binding);
    BOOST_REQUIRE(!out.seed.IsNull());
    const auto result =
        aq::AirQuotientProve<gf::Fp3>(
            out.constraint_system, out.columns, out.seed);
    BOOST_REQUIRE_MESSAGE(result.ok, result.note);
    BOOST_REQUIRE(result.division_exact);
    out.proof = result.proof;
    out.binding.range_child.auxiliary_commitment =
        rc::ComputeRCStage3SignedRangeDualCtlAuxiliaryCommitment(
            out.proof, out.layout, true);
    out.binding.extract_child.auxiliary_commitment =
        rc::ComputeRCStage3SignedRangeDualCtlAuxiliaryCommitment(
            out.proof, out.layout, false);
    BOOST_REQUIRE(
        !out.binding.range_child.auxiliary_commitment.IsNull());
    BOOST_REQUIRE(
        !out.binding.extract_child.auxiliary_commitment.IsNull());
    return out;
}

uint256 DeterministicRangeValueRoot(
    const rc::RCStage3GemmExtractManifest& manifest,
    uint32_t layer)
{
    std::string why;
    const auto bare_pin =
        rc::MakeRCStage3SignedRangePin(manifest, layer, 0, &why);
    BOOST_REQUIRE_MESSAGE(bare_pin.has_value(), why);
    auto pin = *bare_pin;
    std::vector<int64_t> signed_values(pin.logical_rows);
    for (uint32_t i = 0; i < signed_values.size(); ++i) {
        const int64_t magnitude =
            static_cast<int64_t>(i % (pin.max_abs + 1));
        signed_values[i] = i % 3 == 0 ? -magnitude : magnitude;
    }
    std::vector<std::vector<gf::Fp3>> columns;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3SignedRangeColumns(
            pin, signed_values, columns, &why), why);
    const uint32_t aligned_coeffs =
        NextPowerOfTwo(3 * static_cast<uint64_t>(pin.n_rows) - 3);
    return aq::AirCommittedValuesRoot<gf::Fp3>(
        columns[rc::kRCStage3RangeValue], aligned_coeffs);
}

rc::RCStage3GemmExtractObligationManifest Obligations(
    const rc::RCStage3GemmExtractManifest& manifest)
{
    rc::RCStage3GemmExtractObligationManifest out;
    out.statement_commitment = manifest.statement_commitment;
    out.manifest_commitment =
        rc::ComputeRCStage3GemmExtractManifestCommitment(manifest);
    out.layers.resize(manifest.layers.size());
    uint32_t root_byte = 0xb0;
    for (uint32_t i = 0; i < out.layers.size(); ++i) {
        const auto& source = manifest.layers[i].bindings;
        auto& target = out.layers[i];
        target.layer_ordinal = i;
        target.operand_a_root = source.operand_a_root;
        target.operand_b_root = source.operand_b_root;
        target.gemm_y_root = source.gemm_y_root;
        target.extract_input_root = source.extract_input_root;
        target.extract_output_root = source.extract_output_root;
        target.operand_a_opening_commitment =
            Filled(static_cast<unsigned char>(root_byte++));
        target.operand_b_opening_commitment =
            Filled(static_cast<unsigned char>(root_byte++));
        target.gemm_y_opening_commitment =
            Filled(static_cast<unsigned char>(root_byte++));
        target.sumcheck_commitment = source.gemm_proof_root;
        target.signed_range_closure_commitment =
            Filled(static_cast<unsigned char>(root_byte++));
        target.extract_recursive_proof_commitment =
            source.extract_recursive_root;
        target.scale_schedule_proof_commitment =
            source.scale_schedule_root;
        target.range_ctl_child_commitment =
            Filled(static_cast<unsigned char>(root_byte++));
        target.extract_ctl_child_commitment =
            Filled(static_cast<unsigned char>(root_byte++));
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(lambda_manifest_is_exact_compact_and_canonical)
{
    const auto manifest = Manifest();
    const auto layout = rc::RCGkrTraceLayout(manifest.params);
    BOOST_REQUIRE_EQUAL(manifest.layers.size(), layout.layers.size());
    BOOST_REQUIRE_EQUAL(manifest.layers.size(), 4U);

    uint64_t cells{0};
    uint64_t tiles{0};
    for (size_t i = 0; i < manifest.layers.size(); ++i) {
        const auto& layer = manifest.layers[i];
        BOOST_CHECK_EQUAL(layer.ordinal, i);
        BOOST_CHECK_EQUAL(layer.gemm_cell_begin, cells);
        BOOST_CHECK_EQUAL(layer.extract_tile_begin, tiles);
        BOOST_CHECK_EQUAL(layer.gemm_cell_count,
                          static_cast<uint64_t>(layer.m) * layer.n);
        BOOST_CHECK_EQUAL(layer.extract_tile_count,
                          static_cast<uint64_t>(layer.m) *
                              (layer.n / rc::kRCMxBlockLen));
        BOOST_CHECK_EQUAL(layer.signed_max_abs,
                          static_cast<uint64_t>(layer.k) *
                                  rc::kRCMxOperandAbsMax *
                                  rc::kRCMxOperandAbsMax +
                              (layer.residual_first_column >= 0
                                   ? rc::kRCMxOperandAbsMax
                                   : 0));
        cells += layer.gemm_cell_count;
        tiles += layer.extract_tile_count;
    }
    BOOST_CHECK_EQUAL(manifest.total_gemm_cells, cells);
    BOOST_CHECK_EQUAL(manifest.total_extract_tiles, tiles);

    std::vector<unsigned char> encoded;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::SerializeRCStage3GemmExtractManifest(
            manifest, encoded, &why), why);
    const auto decoded =
        rc::DeserializeRCStage3GemmExtractManifest(encoded, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    std::vector<unsigned char> reencoded;
    BOOST_REQUIRE(rc::SerializeRCStage3GemmExtractManifest(
        *decoded, reencoded, &why));
    BOOST_CHECK(reencoded == encoded);
    BOOST_CHECK(
        !rc::ComputeRCStage3GemmExtractManifestCommitment(manifest).IsNull());

    auto reserved = encoded;
    reserved[6] = 1;
    BOOST_CHECK(
        !rc::DeserializeRCStage3GemmExtractManifest(reserved, &why));
    BOOST_CHECK(why.find("manifest_shape") != std::string::npos ||
                why.find("nonzero_reserved") != std::string::npos);

    auto trailing = encoded;
    trailing.push_back(0);
    BOOST_CHECK(
        !rc::DeserializeRCStage3GemmExtractManifest(trailing, &why));
}

BOOST_AUTO_TEST_CASE(manifest_rejects_every_coverage_relabeling_class)
{
    const auto manifest = Manifest();
    std::string why;

    auto omitted = manifest;
    omitted.layers.pop_back();
    BOOST_CHECK(
        !rc::ValidateRCStage3GemmExtractManifest(omitted, &why));
    BOOST_CHECK(why.find("layer_count") != std::string::npos);

    auto duplicated = manifest;
    duplicated.layers[1].gemm_cell_begin =
        duplicated.layers[0].gemm_cell_begin;
    BOOST_CHECK(
        !rc::ValidateRCStage3GemmExtractManifest(duplicated, &why));
    BOOST_CHECK(why.find("coverage_partition") != std::string::npos);

    auto reordered = manifest;
    std::swap(reordered.layers[0], reordered.layers[1]);
    BOOST_CHECK(
        !rc::ValidateRCStage3GemmExtractManifest(reordered, &why));
    BOOST_CHECK(why.find("layout_mismatch") != std::string::npos ||
                why.find("coverage_partition") != std::string::npos);

    auto resized = manifest;
    ++resized.layers[0].extract_tile_count;
    BOOST_CHECK(
        !rc::ValidateRCStage3GemmExtractManifest(resized, &why));
    BOOST_CHECK(why.find("coverage_partition") != std::string::npos);

    auto transposed = manifest;
    transposed.layers[0].a.transpose =
        !transposed.layers[0].a.transpose;
    BOOST_CHECK(
        !rc::ValidateRCStage3GemmExtractManifest(transposed, &why));
    BOOST_CHECK(why.find("layout_mismatch") != std::string::npos);

    auto null_recursive_root = manifest;
    null_recursive_root.layers[0]
        .bindings.extract_recursive_root.SetNull();
    BOOST_CHECK(!rc::ValidateRCStage3GemmExtractManifest(
        null_recursive_root, &why));
    BOOST_CHECK(why.find("null_binding") != std::string::npos);

    auto root_substitution = manifest;
    root_substitution.layers[0].bindings.extract_recursive_root =
        Filled(0xef);
    BOOST_REQUIRE(rc::ValidateRCStage3GemmExtractManifest(
        root_substitution, &why));
    BOOST_CHECK(
        rc::ComputeRCStage3GemmExtractManifestCommitment(manifest) !=
        rc::ComputeRCStage3GemmExtractManifestCommitment(
            root_substitution));

    auto hostile_shape = manifest;
    hostile_shape.params.rounds =
        std::numeric_limits<uint32_t>::max();
    BOOST_CHECK(!rc::ValidateRCStage3GemmExtractManifest(
        hostile_shape, &why));
    BOOST_CHECK(why.find("invalid_params") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(manifest_binds_the_exact_outer_statement)
{
    const auto statement = Statement();
    const auto params = SmallParams();
    std::string why;
    const auto built = rc::BuildRCStage3GemmExtractManifest(
        params, rc::RCStage3EpisodeStatementCommitment(statement),
        Bindings(params), &why);
    BOOST_REQUIRE_MESSAGE(built.has_value(), why);
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3GemmExtractManifestBinding(
            statement, *built, &why), why);

    auto changed = statement;
    changed.public_inputs.sigma = Filled(0x91);
    BOOST_CHECK(!rc::ValidateRCStage3GemmExtractManifestBinding(
        changed, *built, &why));
    BOOST_CHECK(
        why.find("statement_commitment_mismatch") != std::string::npos);

    auto coupled = statement;
    coupled.statement = rc::RCStage3StatementKind::Coupled;
    BOOST_CHECK(!rc::ValidateRCStage3GemmExtractManifestBinding(
        coupled, *built, &why));
    BOOST_CHECK(why.find("coupled_only_statement") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(extract_prfs_bind_verifier_derived_provenance)
{
    const auto manifest = Manifest();
    std::vector<rc::RCGkrSampledLayerProv> provenance(
        manifest.layers.size());
    for (uint32_t i = 0; i < provenance.size(); ++i) {
        const auto& source = manifest.layers[i];
        auto& target = provenance[i];
        target.kind = source.kind;
        target.round = source.round;
        target.layer = source.layer;
        target.m = source.m;
        target.n = source.n;
        target.k = source.k;
        target.extract_prf = source.bindings.extract_prf;
        target.fwd_residual =
            source.residual_first_column >= 0;
    }
    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3GemmExtractLayerProvenance(
            manifest, provenance, &why), why);

    auto substituted = provenance;
    substituted[0].extract_prf = Filled(0xf1);
    BOOST_CHECK(!rc::ValidateRCStage3GemmExtractLayerProvenance(
        manifest, substituted, &why));

    auto relabelled = provenance;
    ++relabelled[0].round;
    BOOST_CHECK(!rc::ValidateRCStage3GemmExtractLayerProvenance(
        manifest, relabelled, &why));

    auto omitted = provenance;
    omitted.pop_back();
    BOOST_CHECK(!rc::ValidateRCStage3GemmExtractLayerProvenance(
        manifest, omitted, &why));
}

BOOST_AUTO_TEST_CASE(profile2_manifest_covers_more_than_uint32_tiles)
{
    const auto params = rc::MakeDatacenterRCEpisodeParams();
    const auto layout = rc::RCGkrTraceLayout(params);
    BOOST_REQUIRE_EQUAL(layout.layers.size(), 400U);
    std::string why;
    const auto built = rc::BuildRCStage3GemmExtractManifest(
        params, Filled(0xc1), Bindings(params), &why);
    BOOST_REQUIRE_MESSAGE(built.has_value(), why);
    const auto& manifest = *built;
    BOOST_CHECK_GT(manifest.total_extract_tiles,
                   std::numeric_limits<uint32_t>::max());
    BOOST_CHECK_EQUAL(manifest.total_extract_tiles, 10'859'069'440ULL);
    BOOST_CHECK_EQUAL(manifest.total_gemm_cells, 347'490'222'080ULL);
    for (const auto& layer : manifest.layers) {
        switch (layer.kind) {
        case rc::RCGkrLayerKind::GemmPhase1QKt:
            BOOST_CHECK_EQUAL(
                layer.signed_max_abs,
                rc::kRCStage3Profile2AccumulatorBounds.qkt_abs_max);
            break;
        case rc::RCGkrLayerKind::GemmPhase1SV:
            BOOST_CHECK_EQUAL(
                layer.signed_max_abs,
                rc::kRCStage3Profile2AccumulatorBounds.sv_abs_max);
            break;
        case rc::RCGkrLayerKind::GemmPhase2FfnUp:
            BOOST_CHECK_EQUAL(
                layer.signed_max_abs,
                rc::kRCStage3Profile2AccumulatorBounds.up_abs_max);
            break;
        case rc::RCGkrLayerKind::GemmPhase2Fwd:
            BOOST_CHECK_EQUAL(
                layer.signed_max_abs,
                rc::kRCStage3Profile2AccumulatorBounds
                    .down_residual_abs_max);
            break;
        default:
            BOOST_FAIL("unexpected episode layer kind");
        }
    }
    std::vector<unsigned char> encoded;
    BOOST_REQUIRE_MESSAGE(
        rc::SerializeRCStage3GemmExtractManifest(
            manifest, encoded, &why), why);
    // v3 bindings carry 5 extra Poseidon VectorRootAlg authority roots per layer.
    BOOST_CHECK_LT(encoded.size(), 300'000U);
}

BOOST_AUTO_TEST_CASE(scale_schedule_is_exactly_partitioned_and_bound)
{
    auto manifest = Manifest();
    std::vector<rc::RCStage3ScaleScheduleShard> all;
    std::string why;
    for (uint32_t layer = 0; layer < manifest.layers.size(); ++layer) {
        std::vector<rc::RCStage3ScaleScheduleShard> group;
        const uint32_t count = static_cast<uint32_t>(
            (manifest.layers[layer].extract_tile_count +
             rc::kRCStage3ScaleScheduleMaxShardTiles - 1) /
            rc::kRCStage3ScaleScheduleMaxShardTiles);
        for (uint32_t shard = 0; shard < count; ++shard) {
            const auto built = rc::BuildRCStage3ScaleScheduleShard(
                manifest, layer, shard, &why);
            BOOST_REQUIRE_MESSAGE(built.has_value(), why);
            group.push_back(*built);
        }
        const uint256 root =
            rc::ComputeRCStage3ScaleScheduleLayerRoot(
                manifest, layer, group, &why);
        BOOST_REQUIRE_MESSAGE(!root.IsNull(), why);
        manifest.layers[layer].bindings.scale_schedule_root = root;
        all.insert(all.end(), group.begin(), group.end());
    }
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3ScaleScheduleClosure(
            manifest, all, true, &why), why);
    BOOST_CHECK(
        why.find("hash_air_pending") != std::string::npos);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3ScaleScheduleClosure(
            manifest, all, false, &why), why);

    auto omitted = all;
    omitted.pop_back();
    BOOST_CHECK(!rc::VerifyRCStage3ScaleScheduleClosure(
        manifest, omitted, false, &why));

    auto reordered = all;
    std::swap(reordered[0], reordered[1]);
    BOOST_CHECK(!rc::VerifyRCStage3ScaleScheduleClosure(
        manifest, reordered, false, &why));

    auto substituted = all;
    substituted[0].scale_commitment = Filled(0xef);
    BOOST_CHECK(!rc::VerifyRCStage3ScaleScheduleClosure(
        manifest, substituted, true, &why));

    auto relabelled = all;
    ++relabelled[0].tile_begin;
    BOOST_CHECK(!rc::VerifyRCStage3ScaleScheduleClosure(
        manifest, relabelled, false, &why));
}

BOOST_AUTO_TEST_CASE(range_to_extract_ctl_pins_close_every_shard)
{
    const auto manifest = Manifest();
    std::vector<rc::RCStage3SignedRangeCtlShard> shards;
    for (uint32_t layer = 0; layer < manifest.layers.size(); ++layer) {
        shards.push_back(CtlShard(manifest, layer));
    }
    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3SignedRangeCtlClosure(
            manifest, shards, &why), why);
    BOOST_CHECK(
        why.find("recursive_air_execution_pending") !=
        std::string::npos);

    auto obligations = Obligations(manifest);
    for (uint32_t layer = 0; layer < obligations.layers.size(); ++layer) {
        obligations.layers[layer].range_ctl_child_commitment =
            rc::ComputeRCStage3SignedRangeCtlLayerCommitment(
                manifest, layer, shards, true, &why);
        obligations.layers[layer].extract_ctl_child_commitment =
            rc::ComputeRCStage3SignedRangeCtlLayerCommitment(
                manifest, layer, shards, false, &why);
    }
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3GemmExtractObligationCtlBinding(
            manifest, obligations, shards, &why), why);

    auto omitted = shards;
    omitted.pop_back();
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeCtlClosure(
        manifest, omitted, &why));
    BOOST_CHECK(why.find("ctl_closure_shard_count") !=
                std::string::npos);

    auto reordered = shards;
    std::swap(reordered[0], reordered[1]);
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeCtlClosure(
        manifest, reordered, &why));
    BOOST_CHECK(why.find("ctl_closure_order") != std::string::npos);

    auto schedule_substitution = shards;
    schedule_substitution[0]
        .binding.range_child.schedule_commitment = Filled(0xe1);
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeCtlClosure(
        manifest, schedule_substitution, &why));

    auto root_substitution = shards;
    root_substitution[0].binding.extract_input_shard_root =
        Filled(0xe2);
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeCtlClosure(
        manifest, root_substitution, &why));

    auto relabelled = shards;
    ++relabelled[0].pin.cell_begin;
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeCtlClosure(
        manifest, relabelled, &why));

    auto obligation_substitution = obligations;
    obligation_substitution.layers[0]
        .range_ctl_child_commitment = Filled(0xe3);
    BOOST_CHECK(
        !rc::ValidateRCStage3GemmExtractObligationCtlBinding(
            manifest, obligation_substitution, shards, &why));

    std::vector<rc::RCStage3SignedRangeShardProof> detached(
        shards.size());
    for (uint32_t i = 0; i < shards.size(); ++i) {
        detached[i].pin = shards[i].pin;
    }
    auto missing_range = detached;
    missing_range.pop_back();
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeProofCtlClosure(
        manifest, missing_range, shards, &why));
    BOOST_CHECK(why.find("range_ctl_closure_count") !=
                std::string::npos);
    auto relabelled_range = detached;
    relabelled_range[0].pin.column_roots[0].root = Filled(0xe4);
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeProofCtlClosure(
        manifest, relabelled_range, shards, &why));
    BOOST_CHECK(why.find("range_ctl_closure_pin") !=
                std::string::npos);
}

BOOST_AUTO_TEST_CASE(proof_obligation_manifest_is_exact_and_fail_closed)
{
    const auto manifest = Manifest();
    auto obligations = Obligations(manifest);
    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3GemmExtractObligationManifest(
            manifest, obligations, &why), why);
    BOOST_CHECK(!rc::ComputeRCStage3GemmExtractObligationCommitment(
                     manifest, obligations)
                     .IsNull());

    auto omitted = obligations;
    omitted.layers.pop_back();
    BOOST_CHECK(!rc::ValidateRCStage3GemmExtractObligationManifest(
        manifest, omitted, &why));

    auto reordered = obligations;
    std::swap(reordered.layers[0], reordered.layers[1]);
    BOOST_CHECK(!rc::ValidateRCStage3GemmExtractObligationManifest(
        manifest, reordered, &why));

    auto root_substitution = obligations;
    root_substitution.layers[0].gemm_y_root = Filled(0xd1);
    BOOST_CHECK(!rc::ValidateRCStage3GemmExtractObligationManifest(
        manifest, root_substitution, &why));

    auto opening_omission = obligations;
    opening_omission.layers[0]
        .operand_a_opening_commitment.SetNull();
    BOOST_CHECK(!rc::ValidateRCStage3GemmExtractObligationManifest(
        manifest, opening_omission, &why));

    auto sumcheck_substitution = obligations;
    sumcheck_substitution.layers[0].sumcheck_commitment =
        Filled(0xd2);
    BOOST_CHECK(!rc::ValidateRCStage3GemmExtractObligationManifest(
        manifest, sumcheck_substitution, &why));

    auto recursive_substitution = obligations;
    recursive_substitution.layers[0]
        .extract_recursive_proof_commitment = Filled(0xd3);
    BOOST_CHECK(!rc::ValidateRCStage3GemmExtractObligationManifest(
        manifest, recursive_substitution, &why));
}

BOOST_AUTO_TEST_CASE(signed_range_air_proves_canonical_integer_embedding)
{
    const auto manifest = Manifest();
    std::string why;
    const auto bare_pin =
        rc::MakeRCStage3SignedRangePin(manifest, 0, 0, &why);
    BOOST_REQUIRE_MESSAGE(bare_pin.has_value(), why);
    auto pin = *bare_pin;
    BOOST_REQUIRE_EQUAL(pin.shard_count, 1U);
    BOOST_REQUIRE_EQUAL(pin.logical_rows,
                        manifest.layers[0].gemm_cell_count);
    BOOST_REQUIRE_EQUAL(pin.n_rows, 1024U);

    std::vector<int64_t> values(pin.logical_rows);
    for (uint32_t i = 0; i < values.size(); ++i) {
        const int64_t magnitude =
            static_cast<int64_t>(i % (pin.max_abs + 1));
        values[i] = i % 3 == 0 ? -magnitude : magnitude;
    }
    values[0] = 0;
    values[1] = static_cast<int64_t>(pin.max_abs);
    values[2] = -static_cast<int64_t>(pin.max_abs);

    std::vector<std::vector<gf::Fp3>> columns;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3SignedRangeColumns(
            pin, values, columns, &why), why);
    BOOST_REQUIRE_EQUAL(columns.size(),
                        rc::kRCStage3SignedRangeColumns);
    for (uint32_t column = 0; column < columns.size(); ++column) {
        pin.column_roots[column].root =
            aq::AirCommittedValuesRoot<gf::Fp3>(
                columns[column], pin.n_rows);
    }

    aq::AirConstraintSystem<gf::Fp3> cs;
    BOOST_REQUIRE_MESSAGE(
        rc::ResolveRCStage3SignedRangeConstraintSystem(
            manifest, pin, cs, &why), why);
    BOOST_CHECK_EQUAL(cs.n_columns,
                      rc::kRCStage3SignedRangeColumns);
    BOOST_CHECK_EQUAL(cs.constraints.size(), 143U);
    uint32_t max_degree{0};
    for (const auto& constraint : cs.constraints) {
        max_degree = std::max(max_degree, constraint.alg_degree);
    }
    BOOST_CHECK_EQUAL(max_degree, 2U);

    const uint256 seed = rc::ComputeRCStage3SignedRangeSeed(pin);
    BOOST_REQUIRE(!seed.IsNull());
    const auto proved =
        aq::AirQuotientProve<gf::Fp3>(cs, columns, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3SignedRangeShard(
            manifest, pin, proved.proof, &why), why);
    BOOST_CHECK(
        why.find("ctl_extract_input_link_pending") != std::string::npos);

    auto root_mutation = pin;
    root_mutation.column_roots[rc::kRCStage3RangeValue].root =
        Filled(0xee);
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeShard(
        manifest, root_mutation, proved.proof, &why));
    BOOST_CHECK(why.find("range_proof_root") != std::string::npos ||
                why.find("range_air") != std::string::npos);

    auto relabelled = pin;
    ++relabelled.cell_begin;
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeShard(
        manifest, relabelled, proved.proof, &why));
    BOOST_CHECK(
        why.find("range_noncanonical_partition") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    episode_signed_range_split_rap_canary_exact_value_export_optional)
{
    BOOST_CHECK(
        rc::kRCStage3EpisodeSignedRangeSplitRapCanaryExecutable);
    BOOST_CHECK(
        !rc::kRCStage3GemmSignedRangeAuthorityReady);
    BOOST_CHECK(
        !rc::kRCStage3SuccinctAuthorityReady);
    const auto& base_columns =
        rc::RCStage3EpisodeSignedRangeSplitRapBaseColumns();
    BOOST_REQUIRE_EQUAL(
        base_columns.size(), 1U);
    BOOST_CHECK_EQUAL(
        base_columns[0],
        rc::kRCStage3RangeValue);

    if (std::getenv(
            "BTX_RUN_STAGE3_SIGNED_RANGE_SPLIT_RAP_CANARY") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_SIGNED_RANGE_SPLIT_RAP_CANARY=1 "
            "to execute the Q192 EpisodeSignedRange Split-RAP canary");
        return;
    }

    const auto manifest = Manifest();
    std::string why;
    const auto bare_pin =
        rc::MakeRCStage3SignedRangePin(
            manifest, 0, 0, &why);
    BOOST_REQUIRE_MESSAGE(
        bare_pin.has_value(), why);
    auto pin = *bare_pin;
    std::vector<int64_t> values(
        pin.logical_rows);
    for (uint32_t row = 0;
         row < values.size(); ++row) {
        const int64_t magnitude =
            static_cast<int64_t>(
                row % (pin.max_abs + 1));
        values[row] =
            row % 3 == 0
                ? -magnitude
                : magnitude;
    }
    values[0] = 0;
    values[1] =
        static_cast<int64_t>(
            pin.max_abs);
    values[2] =
        -static_cast<int64_t>(
            pin.max_abs);

    std::vector<std::vector<gf::Fp3>>
        columns;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3SignedRangeColumns(
            pin, values, columns, &why),
        why);
    for (uint32_t column = 0;
         column < columns.size(); ++column) {
        pin.column_roots[column].root =
            aq::AirCommittedValuesRoot<
                gf::Fp3>(
                    columns[column],
                    pin.n_rows);
    }
    const uint256 expected_export =
        rc::ComputeRCStage3EpisodeSignedRangeSplitRapValueExportRoot(
            pin, values, &why);
    BOOST_REQUIRE_MESSAGE(
        !expected_export.IsNull(), why);

    rc::RCStage3EpisodeSignedRangeSplitRapShardProof
        proof;
    const auto prove_begin =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeSignedRangeSplitRapShard(
            manifest, pin, values,
            proof, &why),
        why);
    const auto prove_ms =
        std::chrono::duration<double,
                              std::milli>(
            std::chrono::steady_clock::now() -
            prove_begin)
            .count();
    const auto verify_begin =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3EpisodeSignedRangeSplitRapShard(
            manifest, pin,
            expected_export, proof, &why),
        why);
    const auto verify_ms =
        std::chrono::duration<double,
                              std::milli>(
            std::chrono::steady_clock::now() -
            verify_begin)
            .count();
    BOOST_TEST_MESSAGE(
        "EpisodeSignedRange Split-RAP canary prove_ms="
        << prove_ms
        << " verify_ms=" << verify_ms);
    BOOST_CHECK(
        why.find("public_cs_reconstructed") !=
        std::string::npos);
    BOOST_REQUIRE_EQUAL(
        proof.quotient.batch.groups.size(),
        3U);
    BOOST_CHECK_EQUAL(
        proof.quotient.batch.groups[0]
            .column_count,
        1U);
    BOOST_CHECK(
        matmul::v4::rc::
            Fri3AlgDigestToUint256(
                proof.quotient.batch
                    .groups[0]
                    .row_commit.root) ==
        proof.value_export_root);

    {
        auto mutated = proof;
        mutated.value_export_root =
            Filled(0xe1);
        BOOST_CHECK(
            !rc::VerifyRCStage3EpisodeSignedRangeSplitRapShard(
                manifest, pin,
                expected_export, mutated,
                &why));
    }
    {
        auto mutated = proof;
        mutated.quotient
            .base_column_indices[0] =
            rc::kRCStage3RangeActive;
        BOOST_CHECK(
            !rc::VerifyRCStage3EpisodeSignedRangeSplitRapShard(
                manifest, pin,
                expected_export, mutated,
                &why));
    }
    {
        auto mutated = proof;
        mutated.quotient.batch.groups[0]
            .row_commit.root[0] =
            gf::Add(
                mutated.quotient.batch
                    .groups[0]
                    .row_commit.root[0],
                1);
        BOOST_CHECK(
            !rc::VerifyRCStage3EpisodeSignedRangeSplitRapShard(
                manifest, pin,
                expected_export, mutated,
                &why));
    }
    {
        auto mutated = proof;
        BOOST_REQUIRE(
            !mutated.quotient.batch
                 .queries.empty());
        BOOST_REQUIRE(
            !mutated.quotient.batch
                 .queries[0]
                 .group_rows[0]
                 .values.empty());
        mutated.quotient.batch
            .queries[0]
            .group_rows[0]
            .values[0] =
            gf::Add(
                mutated.quotient.batch
                    .queries[0]
                    .group_rows[0]
                    .values[0],
                gf::Fp3::One());
        BOOST_CHECK(
            !rc::VerifyRCStage3EpisodeSignedRangeSplitRapShard(
                manifest, pin,
                expected_export, mutated,
                &why));
    }
    {
        auto mutated = proof;
        BOOST_REQUIRE(
            !mutated.quotient.batch
                 .queries.empty());
        BOOST_REQUIRE(
            !mutated.quotient.batch
                 .queries[0]
                 .group_rows[1]
                 .values.empty());
        mutated.quotient.batch
            .queries[0]
            .group_rows[1]
            .values[0] =
            gf::Add(
                mutated.quotient.batch
                    .queries[0]
                    .group_rows[1]
                    .values[0],
                gf::Fp3::One());
        BOOST_CHECK(
            !rc::VerifyRCStage3EpisodeSignedRangeSplitRapShard(
                manifest, pin,
                expected_export, mutated,
                &why));
    }
    {
        auto mutated = proof;
        auto expected = pin;
        mutated.pin.column_roots[
            rc::kRCStage3RangeMagnitude]
            .root = Filled(0xe3);
        expected.column_roots[
            rc::kRCStage3RangeMagnitude]
            .root = Filled(0xe3);
        BOOST_CHECK(
            !rc::VerifyRCStage3EpisodeSignedRangeSplitRapShard(
                manifest, expected,
                expected_export, mutated,
                &why));
    }
    {
        auto relabelled = proof;
        auto expected = pin;
        ++relabelled.pin.cell_begin;
        ++expected.cell_begin;
        BOOST_CHECK(
            !rc::VerifyRCStage3EpisodeSignedRangeSplitRapShard(
                manifest, expected,
                expected_export,
                relabelled, &why));
    }
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeSignedRangeSplitRapShard(
            manifest, pin, Filled(0xe2),
            proof, &why));
}

BOOST_AUTO_TEST_CASE(range_witness_and_air_reject_aliases_and_bad_zero)
{
    const auto manifest = Manifest();
    std::string why;
    auto bare_pin =
        rc::MakeRCStage3SignedRangePin(manifest, 0, 0, &why);
    BOOST_REQUIRE_MESSAGE(bare_pin.has_value(), why);
    auto pin = *bare_pin;
    std::vector<int64_t> values(pin.logical_rows, 0);
    values[0] = static_cast<int64_t>(pin.max_abs) + 1;
    std::vector<std::vector<gf::Fp3>> columns;
    BOOST_CHECK(!rc::BuildRCStage3SignedRangeColumns(
        pin, values, columns, &why));
    BOOST_CHECK(
        why.find("range_witness_out_of_range") != std::string::npos);

    values[0] = 0;
    BOOST_REQUIRE(rc::BuildRCStage3SignedRangeColumns(
        pin, values, columns, &why));
    // Forge "negative zero".  The sign*zero constraint must detect it.
    columns[rc::kRCStage3RangeSign][0] = gf::Fp3::One();
    for (uint32_t column = 0; column < columns.size(); ++column) {
        pin.column_roots[column].root =
            aq::AirCommittedValuesRoot<gf::Fp3>(
                columns[column], pin.n_rows);
    }
    aq::AirConstraintSystem<gf::Fp3> cs;
    BOOST_REQUIRE(rc::ResolveRCStage3SignedRangeConstraintSystem(
        manifest, pin, cs, &why));
    const auto forged = aq::AirQuotientProve<gf::Fp3>(
        cs, columns, rc::ComputeRCStage3SignedRangeSeed(pin));
    BOOST_CHECK(!forged.ok || !forged.division_exact);
}

BOOST_AUTO_TEST_CASE(
    signed_range_value_root_is_equal_to_both_executed_ctl_proofs)
{
    const auto manifest = Manifest();
    const auto canonical = ExecutedCtlShard(manifest, 0);
    std::string why;
    const auto verify_begin = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3SignedRangeExecutedCtlShard(
            manifest, canonical, &why), why);
    const double verify_ms =
        std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - verify_begin)
            .count();
    BOOST_TEST_MESSAGE(
        "aligned signed-range + two executed CTL proof verification ms="
        << verify_ms);
    BOOST_CHECK(
        why.find("extract_opening_and_recursive_consumption_pending") !=
        std::string::npos);
    BOOST_CHECK_EQUAL(
        canonical.range_proof.batch.n_coeffs,
        canonical.range_ctl_proof.batch.n_coeffs);
    BOOST_CHECK(
        canonical.pin.column_roots[rc::kRCStage3RangeValue].root ==
        canonical.range_ctl_proof.batch
            .columns[rc::stage3_ctl_col::VALUE].root);
    BOOST_CHECK(
        canonical.binding.extract_input_shard_root ==
        canonical.extract_ctl_proof.batch
            .columns[rc::stage3_ctl_col::VALUE].root);
    BOOST_CHECK(
        rc::kRCStage3SignedRangeExecutedCtlValueRootBindingExecutable);
    BOOST_CHECK(!rc::kRCStage3GemmSignedRangeAuthorityReady);
    BOOST_CHECK(!rc::kRCStage3ExtractAllTileAuthorityReady);

    auto detached_range_root = canonical;
    detached_range_root.pin
        .column_roots[rc::kRCStage3RangeValue].root = Filled(0xe1);
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeExecutedCtlShard(
        manifest, detached_range_root, &why));
    BOOST_CHECK(
        why.find("range_ctl_aligned_proof_root") !=
        std::string::npos);

    auto substituted_extract_root = canonical;
    substituted_extract_root.binding.extract_input_shard_root =
        Filled(0xe2);
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeExecutedCtlShard(
        manifest, substituted_extract_root, &why));
    BOOST_CHECK(
        why.find("executed_ctl_extract_value_root") !=
        std::string::npos);

    auto detached_ctl_value = canonical;
    detached_ctl_value.range_ctl_proof.batch
        .columns[rc::stage3_ctl_col::VALUE].root = Filled(0xe3);
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeExecutedCtlShard(
        manifest, detached_ctl_value, &why));
    BOOST_CHECK(
        why.find("executed_ctl_range_value_root") !=
        std::string::npos);

    auto relabelled_child = canonical;
    relabelled_child.binding.range_child.role =
        rc::RCStage3RelationRole::EpisodeExtract;
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeExecutedCtlShard(
        manifest, relabelled_child, &why));
    BOOST_CHECK(
        why.find("executed_ctl_air") != std::string::npos);

    auto swapped_proof = canonical;
    swapped_proof.range_ctl_proof =
        canonical.extract_ctl_proof;
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeExecutedCtlShard(
        manifest, swapped_proof, &why));
    BOOST_CHECK(
        why.find("executed_ctl_air") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    signed_range_and_both_ctl_lanes_are_one_proved_trace)
{
    const auto manifest = Manifest();
    const auto canonical = DualCtlDirectAliasShard(manifest, 0);
    std::string why;
    const auto verify_begin = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3SignedRangeDualCtlDirectAliasProof(
            manifest, canonical.pin, canonical.binding,
            canonical.proof, &why),
        why);
    const double verify_ms =
        std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - verify_begin)
            .count();
    BOOST_TEST_MESSAGE(
        "PROOF-LEVEL endpoint9 dual-CTL honest accept: rows="
        << canonical.constraint_system.n_rows
        << " columns=" << canonical.constraint_system.n_columns
        << " constraints="
        << canonical.constraint_system.constraints.size()
        << " n_coeffs=" << canonical.proof.batch.n_coeffs
        << " verify_ms=" << verify_ms);
    BOOST_CHECK(canonical.layout.same_trace_dual_alias);
    BOOST_CHECK_EQUAL(
        canonical.layout.range_columns,
        rc::kRCStage3SignedRangeColumns);
    BOOST_CHECK_EQUAL(
        canonical.layout.total_columns,
        rc::kRCStage3SignedRangeColumns +
            2 * rc::stage3_ctl_col::NUM_COLUMNS);
    const uint256& source_root =
        canonical.proof.batch
            .columns[rc::kRCStage3RangeValue].root;
    BOOST_CHECK(
        source_root ==
        canonical.proof.batch
            .columns[
                canonical.layout.producer_ctl_column_base +
                rc::stage3_ctl_col::VALUE].root);
    BOOST_CHECK(
        source_root ==
        canonical.proof.batch
            .columns[
                canonical.layout.consumer_ctl_column_base +
                rc::stage3_ctl_col::VALUE].root);
    BOOST_CHECK(
        why.find("same_trace_proof_recursive_consumption_pending") !=
        std::string::npos);

    auto detached_aux = canonical.binding;
    detached_aux.extract_child.auxiliary_commitment = Filled(0xe1);
    BOOST_CHECK(
        !rc::VerifyRCStage3SignedRangeDualCtlDirectAliasProof(
            manifest, canonical.pin, detached_aux,
            canonical.proof, &why));
    BOOST_CHECK(
        why.find("ctl_auxiliary_commitment") !=
        std::string::npos);

    // Adversarial proof-level test: change the consumer CTL VALUE after the
    // honest range/producer product is built.  Force the prover to commit the
    // non-divisible quotient, then require the real FRI/AIR verifier—not a
    // host witness counter—to reject the proof.
    auto forged_columns = canonical.columns;
    const uint32_t consumer_value =
        canonical.layout.consumer_ctl_column_base +
        rc::stage3_ctl_col::VALUE;
    forged_columns[consumer_value][3] =
        gf::Add(
            forged_columns[consumer_value][3],
            gf::Fp3::One());
    aq::AirProveOptions adversarial;
    adversarial.force_commit_on_inexact = true;
    const auto forged =
        aq::AirQuotientProve<gf::Fp3>(
            canonical.constraint_system, forged_columns,
            canonical.seed, adversarial);
    BOOST_REQUIRE_MESSAGE(forged.ok, forged.note);
    BOOST_CHECK(!forged.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerify<gf::Fp3>(
            canonical.constraint_system, forged.proof,
            canonical.seed, &why));
    BOOST_TEST_MESSAGE(
        "PROOF-LEVEL endpoint9 forged consumer VALUE rejected by "
        "AirQuotientVerify: " << why);
}

BOOST_AUTO_TEST_CASE(
    extract_input_shard_openings_bind_exact_ordered_layer_root)
{
    auto params = SmallParams();
    params.d_model = 2048;
    params.d_ff = 3072;
    params.b_seq = 1024;
    std::string why;
    const auto built = rc::BuildRCStage3GemmExtractManifest(
        params, Filled(0xb7), Bindings(params), &why);
    BOOST_REQUIRE_MESSAGE(built.has_value(), why);
    auto manifest = *built;
    constexpr uint32_t layer = 2;
    BOOST_REQUIRE_GT(manifest.layers[layer].gemm_cell_count,
                     rc::kRCStage3SignedRangeMaxShardRows);
    const uint32_t shard_count = static_cast<uint32_t>(
        (manifest.layers[layer].gemm_cell_count +
         rc::kRCStage3SignedRangeMaxShardRows - 1) /
        rc::kRCStage3SignedRangeMaxShardRows);
    BOOST_REQUIRE_EQUAL(shard_count, 3U);

    const std::vector<uint256> roots{
        Filled(0xc1), Filled(0xc2), Filled(0xc3)};
    const uint256 layer_root =
        rc::ComputeRCStage3ExtractInputLayerRoot(
            manifest, layer, roots, &why);
    BOOST_REQUIRE_MESSAGE(!layer_root.IsNull(), why);
    manifest.layers[layer].bindings.extract_input_root = layer_root;
    BOOST_REQUIRE_MESSAGE(
        rc::ValidateRCStage3GemmExtractManifest(manifest, &why), why);

    std::vector<rc::RCStage3ExtractInputShardOpening> openings;
    for (uint32_t shard = 0; shard < shard_count; ++shard) {
        const auto opening =
            rc::BuildRCStage3ExtractInputShardOpening(
                manifest, layer, roots, shard, &why);
        BOOST_REQUIRE_MESSAGE(opening.has_value(), why);
        BOOST_CHECK_MESSAGE(
            rc::VerifyRCStage3ExtractInputShardOpening(
                manifest, *opening, &why), why);
        openings.push_back(*opening);
    }
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3ExtractInputLayerOpeningClosure(
            manifest, layer, openings, &why), why);
    BOOST_CHECK(
        why.find("hash_air_and_recursive_consumption_pending") !=
        std::string::npos);

    auto omitted = openings;
    omitted.pop_back();
    BOOST_CHECK(
        !rc::VerifyRCStage3ExtractInputLayerOpeningClosure(
            manifest, layer, omitted, &why));
    BOOST_CHECK(
        why.find("extract_opening_closure_count") !=
        std::string::npos);

    auto reordered = openings;
    std::swap(reordered[0], reordered[1]);
    BOOST_CHECK(
        !rc::VerifyRCStage3ExtractInputLayerOpeningClosure(
            manifest, layer, reordered, &why));
    BOOST_CHECK(
        why.find("extract_opening_closure_order") !=
        std::string::npos);
    auto swapped_roots = roots;
    std::swap(swapped_roots[0], swapped_roots[1]);
    BOOST_CHECK(
        rc::ComputeRCStage3ExtractInputLayerRoot(
            manifest, layer, swapped_roots, &why) != layer_root);

    auto substituted_leaf = openings;
    substituted_leaf[0].shard_root = Filled(0xd1);
    BOOST_CHECK(
        !rc::VerifyRCStage3ExtractInputLayerOpeningClosure(
            manifest, layer, substituted_leaf, &why));
    BOOST_CHECK(
        why.find("extract_opening_layer_root") !=
        std::string::npos);

    auto replayed_path = openings[1];
    replayed_path.authentication_path =
        openings[0].authentication_path;
    BOOST_CHECK(
        !rc::VerifyRCStage3ExtractInputShardOpening(
            manifest, replayed_path, &why));
    BOOST_CHECK(
        why.find("extract_opening_layer_root") !=
        std::string::npos);

    auto substituted_path = openings;
    substituted_path[0].authentication_path[0] = Filled(0xd2);
    BOOST_CHECK(
        !rc::VerifyRCStage3ExtractInputShardOpening(
            manifest, substituted_path[0], &why));
    BOOST_CHECK(
        why.find("extract_opening_layer_root") !=
        std::string::npos);

    auto relabelled = openings[0];
    ++relabelled.cell_begin;
    BOOST_CHECK(
        !rc::VerifyRCStage3ExtractInputShardOpening(
            manifest, relabelled, &why));
    BOOST_CHECK(
        why.find("extract_opening_interval") !=
        std::string::npos);

    auto wrong_registered_root = manifest;
    wrong_registered_root.layers[layer]
        .bindings.extract_input_root = Filled(0xd3);
    BOOST_CHECK(
        !rc::VerifyRCStage3ExtractInputShardOpening(
            wrong_registered_root, openings[0], &why));
    BOOST_CHECK(
        why.find("extract_opening_layer_root") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    executed_ctl_extract_value_is_authenticated_to_layer_root)
{
    auto manifest = Manifest();
    const uint256 shard_root =
        DeterministicRangeValueRoot(manifest, 0);
    BOOST_REQUIRE(!shard_root.IsNull());
    const std::vector<uint256> roots{shard_root};
    const uint256 layer_root =
        rc::ComputeRCStage3ExtractInputLayerRoot(
            manifest, 0, roots);
    BOOST_REQUIRE(!layer_root.IsNull());
    manifest.layers[0].bindings.extract_input_root = layer_root;

    std::string why;
    const auto opening =
        rc::BuildRCStage3ExtractInputShardOpening(
            manifest, 0, roots, 0, &why);
    BOOST_REQUIRE_MESSAGE(opening.has_value(), why);
    rc::RCStage3SignedRangeExecutedCtlOpenedShardProof proof;
    proof.extract_input_opening = *opening;
    proof.relation = ExecutedCtlShard(
        manifest, 0, &proof.extract_input_opening);

    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3SignedRangeExecutedCtlOpenedShard(
            manifest, proof, &why), why);
    BOOST_CHECK(
        why.find("authenticated_to_layer_extract_input_root") !=
        std::string::npos);
    BOOST_CHECK(
        proof.relation.binding.extract_input_shard_root ==
        proof.extract_input_opening.shard_root);
    BOOST_CHECK(
        proof.relation.binding.extract_input_opening_commitment ==
        rc::ComputeRCStage3ExtractInputShardOpeningCommitment(
            manifest, proof.relation.pin,
            proof.extract_input_opening));
    BOOST_CHECK(
        rc::kRCStage3ExtractInputShardToLayerOpeningExecutable);
    BOOST_CHECK(!rc::kRCStage3GemmSignedRangeAuthorityReady);
    BOOST_CHECK(!rc::kRCStage3ExtractAllTileAuthorityReady);

    auto leaf_substitution = proof;
    leaf_substitution.extract_input_opening.shard_root =
        Filled(0xe5);
    BOOST_CHECK(
        !rc::VerifyRCStage3SignedRangeExecutedCtlOpenedShard(
            manifest, leaf_substitution, &why));
    BOOST_CHECK(
        why.find("opened_ctl_interval_or_root") !=
        std::string::npos);

    auto detached_opening_commitment = proof;
    detached_opening_commitment.relation.binding
        .extract_input_opening_commitment = Filled(0xe6);
    BOOST_CHECK(
        !rc::VerifyRCStage3SignedRangeExecutedCtlOpenedShard(
            manifest, detached_opening_commitment, &why));

    std::vector<rc::RCStage3SignedRangeExecutedCtlOpenedShardProof>
        omitted_global{proof};
    BOOST_CHECK(
        !rc::VerifyRCStage3SignedRangeExecutedCtlOpenedClosure(
            manifest, omitted_global, &why));
    BOOST_CHECK(
        why.find("opened_ctl_closure_count") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(all_shard_closure_fails_closed_on_omission)
{
    const auto manifest = Manifest();
    std::vector<rc::RCStage3SignedRangeShardProof> none;
    std::vector<rc::RCStage3SignedRangeExecutedCtlShardProof>
        no_executed_ctl;
    std::string why;
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeClosure(
        manifest, none, &why));
    BOOST_CHECK(
        why.find("range_closure_shard_count") != std::string::npos);
    BOOST_CHECK(!rc::VerifyRCStage3SignedRangeExecutedCtlClosure(
        manifest, no_executed_ctl, &why));
    BOOST_CHECK(
        why.find("executed_ctl_closure_shard_count") !=
        std::string::npos);
    BOOST_CHECK(!rc::kRCStage3GemmExtractManifestComplete);
    BOOST_CHECK(!rc::kRCStage3GemmSignedRangeAuthorityReady);
    BOOST_CHECK(!rc::kRCStage3ExtractAllTileAuthorityReady);
    BOOST_CHECK(rc::kRCStage3EpisodeRelationsReady);
    BOOST_CHECK(!rc::kRCStage3SuccinctAuthorityReady);
}

BOOST_AUTO_TEST_SUITE_END()
