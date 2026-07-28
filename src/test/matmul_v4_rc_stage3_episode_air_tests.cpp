// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_air.h>

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace aq = matmul::v4::rc::air_quotient;
namespace cb = matmul::v4::rc::constraint_bytecode;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_episode_air_tests,
                         BasicTestingSetup)

namespace {

uint256 Filled(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
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

rc::RCStage3EpisodeAirPublicPin BasePin(
    const rc::RCStage3SuccinctProof& statement,
    rc::RCStage3RelationRole role,
    rc::RCStage3EpisodeAirFamily family,
    uint32_t columns,
    uint32_t n_rows = 8)
{
    rc::RCStage3EpisodeAirPublicPin pin;
    pin.role = role;
    pin.family = family;
    pin.statement_commitment =
        rc::RCStage3EpisodeStatementCommitment(statement);
    pin.shard_count = 1;
    pin.logical_rows = n_rows;
    pin.n_rows = n_rows;
    pin.n_coeffs =
        family ==
                rc::RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1
            ? [&] {
                  uint32_t out = 1;
                  while (out < 3 * n_rows - 3) out <<= 1;
                  return out;
              }()
            : n_rows;
    for (uint32_t i = 0; i < columns; ++i) {
        pin.column_roots.push_back(
            {i, Filled(static_cast<unsigned char>(i + 1))});
    }
    return pin;
}

uint256 MakePrf(uint8_t seed)
{
    std::array<uint8_t, 32> bytes{};
    for (int i = 0; i < 32; ++i) {
        bytes[i] = static_cast<uint8_t>(seed * 7 + i * 31 + 1);
    }
    return uint256{
        Span<const unsigned char>{bytes.data(), bytes.size()}};
}

std::array<int64_t, rc::kRCMxBlockLen> MakeInput(int64_t base)
{
    std::array<int64_t, rc::kRCMxBlockLen> input{};
    for (uint32_t i = 0; i < input.size(); ++i) {
        const int64_t value = base + static_cast<int64_t>(i) * 977;
        input[i] = i % 3 == 0 ? -value : value;
    }
    input[5] = int64_t{1} << 40;
    input[9] = -(int64_t{1} << 45);
    return input;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 1;
    while (out < value) out <<= 1;
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(registry_is_immutable_partial_and_proof_only)
{
    const auto caps = rc::CurrentRCStage3EpisodeAirCapabilities();
    BOOST_REQUIRE_EQUAL(caps.size(), 3U);
    BOOST_CHECK(caps[0].role == rc::RCStage3RelationRole::EpisodeGemm);
    BOOST_CHECK(caps[1].role == rc::RCStage3RelationRole::EpisodeExtract);
    BOOST_CHECK(caps[2].role == rc::RCStage3RelationRole::EpisodeWiring);
    for (const auto& cap : caps) {
        BOOST_CHECK(cap.proof_only);
        BOOST_CHECK(!cap.complete_role);
        BOOST_REQUIRE(cap.detail != nullptr);
    }
    BOOST_CHECK(!rc::kRCStage3EpisodeAirRegistryComplete);
    BOOST_CHECK(rc::kRCStage3EpisodeRelationsReady);
    BOOST_CHECK(!rc::kRCStage3SuccinctAuthorityReady);
}

BOOST_AUTO_TEST_CASE(public_pin_codec_is_canonical_and_cycle_free)
{
    const auto statement = Statement();
    const auto pin = BasePin(
        statement, rc::RCStage3RelationRole::EpisodeGemm,
        rc::RCStage3EpisodeAirFamily::GemmEndpointFp3V1, 3);
    std::vector<unsigned char> bytes;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::SerializeRCStage3EpisodeAirPublicPin(pin, bytes, &why), why);
    const auto decoded =
        rc::DeserializeRCStage3EpisodeAirPublicPin(bytes, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    BOOST_CHECK(*decoded == pin);
    BOOST_CHECK(!rc::ComputeRCStage3EpisodeAirPinCommitment(pin).IsNull());

    auto transcript_changed = statement;
    transcript_changed.public_inputs.transcript_commitment = Filled(0xee);
    BOOST_CHECK(
        rc::ComputeRCStage3EpisodeAirSeed(statement, pin) ==
        rc::ComputeRCStage3EpisodeAirSeed(transcript_changed, pin));

    auto root_changed = pin;
    root_changed.column_roots[0].root = Filled(0xab);
    BOOST_CHECK(
        rc::ComputeRCStage3EpisodeAirSeed(statement, pin) ==
        rc::ComputeRCStage3EpisodeAirSeed(statement, root_changed));
    BOOST_CHECK(
        rc::ComputeRCStage3EpisodeAirPinCommitment(pin) !=
        rc::ComputeRCStage3EpisodeAirPinCommitment(root_changed));

    auto reserved = bytes;
    reserved[11] = 1;
    BOOST_CHECK(
        !rc::DeserializeRCStage3EpisodeAirPublicPin(reserved, &why));
    BOOST_CHECK(why.find("nonzero_reserved") != std::string::npos);

    auto trailing = bytes;
    trailing.push_back(0);
    BOOST_CHECK(
        !rc::DeserializeRCStage3EpisodeAirPublicPin(trailing, &why));
    BOOST_CHECK(why.find("noncanonical_root_length") != std::string::npos ||
                why.find("pin_size") != std::string::npos);

    auto wrong_order = pin;
    wrong_order.column_roots[1].column = 0;
    BOOST_CHECK(!rc::SerializeRCStage3EpisodeAirPublicPin(
        wrong_order, bytes, &why));
    BOOST_CHECK(why.find("noncanonical_column_order") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(resolver_exposes_three_concrete_air_shapes)
{
    const auto statement = Statement();
    std::string why;
    aq::AirConstraintSystem<gf::Fp3> cs;

    const auto gemm = BasePin(
        statement, rc::RCStage3RelationRole::EpisodeGemm,
        rc::RCStage3EpisodeAirFamily::GemmEndpointFp3V1, 3);
    BOOST_REQUIRE_MESSAGE(
        rc::ResolveRCStage3EpisodeAirConstraintSystem(
            statement, gemm, cs, &why), why);
    BOOST_CHECK_EQUAL(cs.n_columns, 3U);
    BOOST_CHECK_EQUAL(cs.constraints.size(), 1U);
    BOOST_CHECK_EQUAL(cs.preprocessed_roots.size(), 3U);

    auto extract = BasePin(
        statement, rc::RCStage3RelationRole::EpisodeExtract,
        rc::RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1,
        aq::kRcSamplerNumCols);
    extract.extract_scale_e = 2;
    BOOST_REQUIRE_MESSAGE(
        rc::ResolveRCStage3EpisodeAirConstraintSystem(
            statement, extract, cs, &why), why);
    BOOST_CHECK_EQUAL(cs.n_columns, aq::kRcSamplerNumCols);
    BOOST_CHECK_GT(cs.constraints.size(), 10U);
    BOOST_CHECK_EQUAL(
        cs.preprocessed_roots.size(), aq::kRcSamplerNumCols);

    const auto wiring = BasePin(
        statement, rc::RCStage3RelationRole::EpisodeWiring,
        rc::RCStage3EpisodeAirFamily::WiringEqualityFp3V1, 2);
    BOOST_REQUIRE_MESSAGE(
        rc::ResolveRCStage3EpisodeAirConstraintSystem(
            statement, wiring, cs, &why), why);
    BOOST_CHECK_EQUAL(cs.n_columns, 2U);
    BOOST_CHECK_EQUAL(cs.constraints.size(), 1U);

    auto mismatch = wiring;
    mismatch.role = rc::RCStage3RelationRole::EpisodeExtract;
    BOOST_CHECK(!rc::ResolveRCStage3EpisodeAirConstraintSystem(
        statement, mismatch, cs, &why));
    BOOST_CHECK(why.find("family_role_mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(gemm_endpoint_shard_verifies_without_native_witness)
{
    const auto statement = Statement();
    constexpr uint32_t N = 8;
    std::vector<std::vector<gf::Fp3>> columns(3);
    for (uint32_t i = 0; i < N; ++i) {
        const gf::Fp3 a = gf::Fp3::FromFp(i + 2);
        const gf::Fp3 b = gf::Fp3::FromFp(3 * i + 1);
        columns[0].push_back(gf::Mul(a, b));
        columns[1].push_back(a);
        columns[2].push_back(b);
    }

    auto pin = BasePin(
        statement, rc::RCStage3RelationRole::EpisodeGemm,
        rc::RCStage3EpisodeAirFamily::GemmEndpointFp3V1, 3);
    for (uint32_t i = 0; i < columns.size(); ++i) {
        pin.column_roots[i].root =
            aq::AirCommittedValuesRoot<gf::Fp3>(columns[i], N);
    }

    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::ResolveRCStage3EpisodeAirConstraintSystem(
            statement, pin, cs, &why), why);
    const uint256 seed =
        rc::ComputeRCStage3EpisodeAirSeed(statement, pin);
    const auto proved =
        aq::AirQuotientProve<gf::Fp3>(cs, columns, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeAirShard(
            statement, pin, proved.proof, &why), why);
    BOOST_CHECK(why.find("role_incomplete") != std::string::npos);

    auto root_mutation = pin;
    root_mutation.column_roots[1].root = Filled(0xa5);
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeAirShard(
        statement, root_mutation, proved.proof, &why));
    BOOST_CHECK(why.find("column_root_mismatch") != std::string::npos);

    auto statement_mutation = statement;
    statement_mutation.public_inputs.sigma = Filled(0xf0);
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeAirShard(
        statement_mutation, pin, proved.proof, &why));
    BOOST_CHECK(why.find("statement_commitment_mismatch") !=
                std::string::npos);
}

BOOST_AUTO_TEST_CASE(extract_sampler_shard_honest_roundtrip_and_mutations)
{
    namespace air = matmul::v4::rc::gkr_air;
    const auto statement = Statement();
    air::TilePublic tile_public;
    tile_public.prf_key = MakePrf(17);
    tile_public.i = 3;
    tile_public.bj = 7;
    const air::TileWitness witness =
        air::TraceTile(tile_public, MakeInput(1000));
    const uint32_t n_rows = NextPowerOfTwo(
        std::max<uint32_t>(
            static_cast<uint32_t>(witness.cands.size()),
            rc::kRCMxBlockLen + 1));

    auto pin = BasePin(
        statement, rc::RCStage3RelationRole::EpisodeExtract,
        rc::RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1,
        aq::kRcSamplerNumCols, n_rows);
    pin.logical_rows = static_cast<uint32_t>(witness.cands.size());
    pin.extract_scale_e = witness.scale_e;
    const uint256 seed =
        rc::ComputeRCStage3EpisodeAirSeed(statement, pin);
    BOOST_REQUIRE(!seed.IsNull());

    const air::TableTM tm;
    const auto instance =
        aq::BuildRcSamplerInstance<gf::Fp3>(witness, tm, seed);
    BOOST_REQUIRE_MESSAGE(instance.ok, instance.note);
    BOOST_REQUIRE_EQUAL(instance.n_rows, pin.n_rows);
    BOOST_REQUIRE_EQUAL(pin.n_coeffs, NextPowerOfTwo(
        std::max(pin.n_rows, instance.cs.QuotientLen())));

    const auto proved =
        aq::AirQuotientProve<gf::Fp3>(
            instance.cs, instance.columns, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_REQUIRE_EQUAL(
        proved.proof.batch.columns.size(),
        static_cast<size_t>(aq::kRcSamplerNumCols) + 1);
    BOOST_REQUIRE_EQUAL(proved.proof.batch.n_coeffs, pin.n_coeffs);
    for (uint32_t i = 0; i < aq::kRcSamplerNumCols; ++i) {
        pin.column_roots[i].root = proved.proof.batch.columns[i].root;
    }
    // Filling the complete pin after the two-epoch proof is formed must not
    // alter the external base seed.
    BOOST_CHECK(
        rc::ComputeRCStage3EpisodeAirSeed(statement, pin) == seed);

    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeAirShard(
            statement, pin, proved.proof, &why), why);

    auto root_mutation = pin;
    root_mutation.column_roots[aq::kColOut].root = Filled(0xa5);
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeAirShard(
        statement, root_mutation, proved.proof, &why));
    BOOST_CHECK(why.find("column_root_mismatch") != std::string::npos);

    auto scale_mutation = pin;
    scale_mutation.extract_scale_e ^= 1;
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeAirShard(
        statement, scale_mutation, proved.proof, &why));
}

BOOST_AUTO_TEST_CASE(readiness_and_six_role_gaps_are_exact)
{
    const auto statement = Statement();
    const auto pin = BasePin(
        statement, rc::RCStage3RelationRole::EpisodeGemm,
        rc::RCStage3EpisodeAirFamily::GemmEndpointFp3V1, 3);
    const auto readiness =
        rc::AssessRCStage3EpisodeAirReadiness(statement, pin);
    BOOST_CHECK(readiness.structurally_valid);
    BOOST_CHECK(readiness.constraint_system_resolved);
    BOOST_CHECK(readiness.proof_only);
    BOOST_CHECK(!readiness.role_complete);
    BOOST_CHECK_NE(readiness.locally_enforced_obligations, 0U);
    BOOST_CHECK_NE(readiness.missing_obligations, 0U);
    BOOST_CHECK_GE(readiness.gaps.size(), 3U);

    const auto gaps = rc::CurrentRCStage3EpisodeAirRoleGaps();
    const auto roles =
        rc::RequiredRCStage3RelationRoles(
            rc::RCStage3StatementKind::Episode);
    BOOST_REQUIRE_EQUAL(gaps.size(), roles.size());
    for (size_t i = 0; i < gaps.size(); ++i) {
        BOOST_CHECK(gaps[i].role == roles[i]);
        BOOST_CHECK_NE(gaps[i].missing_obligations, 0U);
        BOOST_CHECK(!gaps[i].reason.empty());
    }
}

// EpisodeExtract local kernel: the migrated RcSampler ProgramTable is bit-
// identical to air_quotient::BuildRcSamplerConstraintSystem for every public
// scale exponent over random rows and the [gamma, alpha] challenge, and the
// family entry point no longer returns the not-migrated stub.
BOOST_AUTO_TEST_CASE(
    episode_extract_local_kernel_bytecode_matches_native_rc_sampler)
{
    const gf::Fp3 gamma = gf::FromU64_3(0x0abc1234u);
    const gf::Fp3 alpha = gf::FromU64_3(0x0def5678u);
    const std::vector<gf::Fp3> challenge{gamma, alpha};
    const rc::gkr_air::TableTM tm;

    // The family entry point now yields a real table (canonical scale_e=0) and
    // is no longer the "extract_bytecode_not_migrated" stub.
    cb::ProgramTable family_table;
    std::string family_why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeLocalKernelProgramTable(
            rc::RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1,
            family_table, &family_why),
        family_why);
    BOOST_CHECK(
        family_table.role == rc::RCStage3RelationRole::EpisodeExtract);
    BOOST_CHECK_EQUAL(family_table.current_width, aq::kRcSamplerNumCols);
    BOOST_CHECK_EQUAL(family_table.challenge_width, 2U);
    BOOST_CHECK_EQUAL(family_table.programs.size(), 47U);

    uint32_t total_mismatches = 0;
    for (uint8_t scale_e = 0; scale_e <= 3; ++scale_e) {
        cb::ProgramTable table;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            rc::BuildRCStage3EpisodeExtractLocalKernelProgramTable(
                scale_e, table, &why),
            why);
        BOOST_CHECK(
            table.role == rc::RCStage3RelationRole::EpisodeExtract);
        BOOST_CHECK_EQUAL(table.current_width, aq::kRcSamplerNumCols);
        BOOST_CHECK_EQUAL(table.challenge_width, 2U);
        BOOST_CHECK(cb::ProgramTableIsChallengeIndependent(table));

        const auto native =
            aq::BuildRcSamplerConstraintSystem<gf::Fp3>(
                /*n_rows=*/8, gamma, alpha, scale_e, tm);
        BOOST_REQUIRE_EQUAL(
            table.programs.size(), native.constraints.size());
        BOOST_CHECK_EQUAL(table.programs.size(), 47U);

        // The episode kernel reuses the coupled emit: identical instructions,
        // but the role-bound commitment differs (anti cross-role replay).
        cb::ProgramTable coupled;
        BOOST_REQUIRE(
            rc::BuildRCStage3CoupledExtractLocalKernelProgramTable(
                scale_e, coupled, &why));
        BOOST_REQUIRE_EQUAL(
            table.programs.size(), coupled.programs.size());
        for (uint32_t i = 0; i < table.programs.size(); ++i) {
            BOOST_CHECK(
                table.programs[i].instructions ==
                coupled.programs[i].instructions);
        }
        BOOST_CHECK(
            cb::CommitProgramTable(table) != cb::CommitProgramTable(coupled));

        uint64_t rng = 0x243F6A8885A308D3ULL + scale_e;
        const auto next_field = [&rng]() {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            return gf::FromU64_3(rng);
        };
        for (uint32_t trial = 0; trial < 64; ++trial) {
            std::vector<gf::Fp3> current(table.current_width);
            std::vector<gf::Fp3> next(table.current_width);
            for (auto& v : current) v = next_field();
            for (auto& v : next) v = next_field();
            for (uint32_t i = 0; i < table.programs.size(); ++i) {
                const gf::Fp3 native_value =
                    native.constraints[i].eval(current, next);
                gf::Fp3 interpreted;
                BOOST_REQUIRE(cb::EvaluateProgram(
                    table.programs[i], current, next, challenge,
                    interpreted));
                if (!gf::Eq(native_value, interpreted)) ++total_mismatches;
            }
        }
    }
    BOOST_CHECK_EQUAL(total_mismatches, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
