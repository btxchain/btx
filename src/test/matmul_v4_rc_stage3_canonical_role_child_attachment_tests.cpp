// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_canonical_role_child_attachment.h>
#include <test/util/setup_common.h>

#include <consensus/params.h>
#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>
#include <matmul/matmul_v4_rc_stage3_universal_topology.h>
#include <primitives/block.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>

namespace {

namespace attach =
    matmul::v4::rc::canonical_role_child_attachment;
namespace aq = matmul::v4::rc::air_quotient;
namespace cpv =
    matmul::v4::rc::canonical_parent_production_verifier;
namespace gf = matmul::v4::rc::gkr_field;
namespace cb = matmul::v4::rc::constraint_bytecode;
namespace rfp = matmul::v4::rc::recursive_fixedpoint;
namespace ut = matmul::v4::rc::universal_topology;

CBlock Block()
{
    CBlock out;
    out.nVersion = 4;
    out.nTime = 1;
    out.nBits = 0x207fffffU;
    out.nNonce64 = 7;
    out.matmul_dim = 256;
    return out;
}

Consensus::Params Params()
{
    Consensus::Params out;
    out.fMatMulPOW = true;
    out.nMatMulV4Height = 1;
    out.nMatMulRCHeight = 1;
    out.nMatMulRCProfile = 2;
    out.fMatMulRCUseToyDims = true;
    out.nMatMulV4Dimension = 256;
    out.nMatMulRCCoupledHeight = 1;
    out.nMatMulRCCoupledProfile = 3;
    out.fMatMulRCCoupledUseToyDims = true;
    return out;
}

uint256 Filled(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

struct NativeChildFixture {
    cb::ProgramTable program;
    uint32_t rows{0};
    std::vector<uint32_t> r0_columns;
    uint256 seed{};
    aq::AirQuotientSplitRapRowsProof proof;
};

NativeChildFixture BuildNativeChildFixture()
{
    NativeChildFixture out;
    out.rows = 8;
    out.r0_columns = {0, 1};
    out.seed = Filled(0x5a);
    out.program.role =
        matmul::v4::rc::RCStage3RelationRole::
            EpisodeDeterministicBuilder;
    out.program.current_width = 4;
    out.program.next_width = 4;
    out.program.challenge_width = 1;

    cb::Program relation;
    relation.role = out.program.role;
    relation.constraint_ordinal = 0;
    relation.kind = aq::AirKind::kEverywhere;
    relation.declared_degree = 2;
    relation.current_width = 4;
    relation.next_width = 4;
    relation.challenge_width = 1;
    relation.instructions = {
        {cb::Opcode::Current, 2, 0, gf::Fp3::Zero()},
        {cb::Opcode::Current, 0, 0, gf::Fp3::Zero()},
        {cb::Opcode::Challenge, 0, 0, gf::Fp3::Zero()},
        {cb::Opcode::Current, 1, 0, gf::Fp3::Zero()},
        {cb::Opcode::Mul, 2, 3, gf::Fp3::Zero()},
        {cb::Opcode::Add, 1, 4, gf::Fp3::Zero()},
        {cb::Opcode::Sub, 0, 5, gf::Fp3::Zero()},
    };
    out.program.programs.push_back(std::move(relation));

    cb::Program transition;
    transition.role = out.program.role;
    transition.constraint_ordinal = 1;
    transition.kind = aq::AirKind::kTransition;
    transition.declared_degree = 1;
    transition.current_width = 4;
    transition.next_width = 4;
    transition.challenge_width = 1;
    transition.instructions = {
        {cb::Opcode::Next, 3, 0, gf::Fp3::Zero()},
        {cb::Opcode::Current, 3, 0, gf::Fp3::Zero()},
        {cb::Opcode::Current, 2, 0, gf::Fp3::Zero()},
        {cb::Opcode::Add, 1, 2, gf::Fp3::Zero()},
        {cb::Opcode::Sub, 0, 3, gf::Fp3::Zero()},
    };
    out.program.programs.push_back(std::move(transition));
    BOOST_REQUIRE(cb::ValidateProgramTable(out.program));

    std::vector<std::vector<gf::Fp3>> columns(
        out.program.current_width,
        std::vector<gf::Fp3>(
            out.rows, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < out.rows; ++row) {
        columns[0][row] =
            gf::Fp3::FromFp(
                gf::FromU64(3 + row * row));
        columns[1][row] =
            gf::Fp3::FromFp(
                gf::FromU64(5 + 2 * row));
    }
    std::vector<gf::Fp3> zero_challenge{
        gf::Fp3::Zero()};
    aq::AirConstraintSystem<gf::Fp3> shape_cs;
    BOOST_REQUIRE(
        cb::BuildAirConstraintSystemFromProgramTable(
            out.program, out.rows,
            zero_challenge, shape_cs));
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            shape_cs, columns, out.r0_columns);
    BOOST_REQUIRE_MESSAGE(r0.valid, r0.note);
    std::vector<gf::Fp3> challenges;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rfp::DeriveBytecodeChallengeVectorV1(
            out.program, out.rows,
            out.r0_columns, out.seed,
            r0.base_row_commitment,
            challenges, &why),
        why);
    BOOST_REQUIRE_EQUAL(challenges.size(), 1U);
    for (uint32_t row = 0; row < out.rows; ++row) {
        columns[2][row] =
            gf::Add(
                columns[0][row],
                gf::Mul(
                    challenges[0],
                    columns[1][row]));
        if (row + 1 < out.rows) {
            columns[3][row + 1] =
                gf::Add(
                    columns[3][row],
                    columns[2][row]);
        }
    }
    aq::AirConstraintSystem<gf::Fp3> cs;
    BOOST_REQUIRE(
        cb::BuildAirConstraintSystemFromProgramTable(
            out.program, out.rows,
            challenges, cs));
    BOOST_REQUIRE_EQUAL(
        matmul::v4::rc::air_recurse::
            CountWitnessViolationsOnH(cs, columns),
        0U);
    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            cs, columns, out.r0_columns,
            out.seed, {}, &r0);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    out.proof = proved.proof;
    return out;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_canonical_role_child_attachment_tests,
    BasicTestingSetup)

BOOST_AUTO_TEST_CASE(
    production_phase_schedule_is_rebuilt_but_empty_proofs_fail_closed)
{
    CBlock block = Block();
    Consensus::Params params = Params();
    auto assessment =
        cpv::AssessFrozenBinaryParentSpecV1(
            block, params, 101);
    const auto pin =
        ut::BuildProductionProgramConsensusPinV1(
            assessment.registry.diagnostic_registry);
    params.hashMatMulRCStage3ProgramRegistryAlgRoot =
        pin.recursive_alg_hash_root;
    params.hashMatMulRCStage3ProgramRegistryShaAuditRoot =
        pin.external_sha256d_audit_root;
    params.hashMatMulRCStage3ProgramRegistryBinding =
        pin.registry_binding;
    assessment =
        cpv::AssessFrozenBinaryParentSpecV1(
            block, params, 101);
    BOOST_REQUIRE(assessment.consensus_registry_pin_matches);
    BOOST_REQUIRE(
        assessment.role_half_r0_schedules_available);
    BOOST_CHECK_EQUAL(
        assessment.residual_mask &
            cpv::kResidualRoleHalfR0Schedule,
        0U);
    BOOST_CHECK(
        assessment.missing_r0_phase_family_indices.empty());
    BOOST_CHECK(
        !assessment.diagnostic_child_r0_base_columns[0].empty());
    BOOST_CHECK(
        !assessment.diagnostic_child_r0_base_columns[1].empty());
    BOOST_CHECK(
        !assessment.diagnostic_child_phase_commitment[0].IsNull());
    BOOST_CHECK(
        !assessment.diagnostic_child_phase_commitment[1].IsNull());

    // All seven challenge-bearing families export their exact witness-phase
    // split; challenge-free family schedules are earned mechanically.
    const auto sources =
        ut::BuildProductionFamilyProgramSourcesV1(
            assessment.site_manifest);
    uint32_t challenge_bearing = 0;
    uint32_t exported = 0;
    for (const auto& source : sources) {
        std::string phase_why;
        if (source.program.challenge_width == 0) {
            BOOST_CHECK_MESSAGE(
                ut::ValidateProductionFamilyPhaseDescriptorV1(
                    source.program, source.phase,
                    /*require_producer_export=*/true,
                    &phase_why),
                phase_why);
            ++exported;
            continue;
        }
        ++challenge_bearing;
        BOOST_CHECK(
            source.phase.producer_manifest_exported);
        BOOST_CHECK(
            !source.phase.r0_base_columns.empty());
        BOOST_CHECK(
            ut::ValidateProductionFamilyPhaseDescriptorV1(
                source.program, source.phase,
                /*require_producer_export=*/true,
                &phase_why));
        ++exported;
    }
    BOOST_CHECK_GT(challenge_bearing, 0U);
    BOOST_CHECK_GT(exported, 0U);

    // Empty/default proof objects cannot be promoted merely because the
    // independently reconstructed phase schedule now exists.
    std::array<
        aq::AirQuotientSplitRapRowsProof, 2> proofs{};
    std::vector<unsigned char> encoded;
    std::string why;
    BOOST_CHECK(
        !attach::SerializeAgainstAssessmentV1(
            assessment, proofs, encoded, &why));
    BOOST_CHECK(encoded.empty());
    attach::ValidatedPairV1 production;
    BOOST_CHECK(
        !attach::DecodeAndValidateV1(
            block, params, 101, {},
            production, &why));
    BOOST_CHECK(!production.valid);
}

BOOST_AUTO_TEST_CASE(
    child_identity_binds_phase_commitment_and_exact_r0_order)
{
    const uint256 program = Filled(0x11);
    const uint256 shape = Filled(0x22);
    const uint256 phase = Filled(0x33);
    const std::vector<uint32_t> base{0, 2, 5, 8};
    const uint256 honest =
        attach::ComputeChildIdentityV1(
            0, program, shape, phase, base);
    BOOST_REQUIRE(!honest.IsNull());
    auto shifted = base;
    ++shifted[2];
    BOOST_CHECK_NE(
        attach::ComputeChildIdentityV1(
            0, program, shape, phase, shifted),
        honest);
    auto reordered = base;
    std::swap(reordered[1], reordered[2]);
    BOOST_CHECK_NE(
        attach::ComputeChildIdentityV1(
            0, program, shape, phase, reordered),
        honest);
    BOOST_CHECK_NE(
        attach::ComputeChildIdentityV1(
            1, program, shape, phase, base),
        honest);
    BOOST_CHECK_NE(
        attach::ComputeChildIdentityV1(
            0, program, shape, Filled(0x34), base),
        honest);
}

BOOST_AUTO_TEST_CASE(
    canonical_family_phase_inventory_rejects_schedule_substitution)
{
    const auto manifest =
        matmul::v4::rc::soundness_scenarios::
            BuildProductionProofSiteManifest(
                matmul::v4::rc::soundness_scenarios::
                    SelectedProductionProofSitePolicy());
    const auto sources =
        ut::BuildProductionFamilyProgramSourcesV1(
            manifest);
    uint32_t challenge_bearing = 0;
    for (const auto& source : sources) {
        if (source.program.challenge_width != 0) {
            ++challenge_bearing;
            BOOST_CHECK(
                source.phase.producer_manifest_exported);
            BOOST_TEST_MESSAGE(
                "R0_PHASE_EXPORTED family="
                << source.family_index
                << " kind="
                << static_cast<uint16_t>(source.kind)
                << " role="
                << static_cast<uint16_t>(source.role)
                << " columns="
                << source.program.current_width
                << " r0="
                << source.phase.r0_base_columns.size()
                << " rdep="
                << source.program.current_width -
                       source.phase.r0_base_columns.size());
        }
    }
    BOOST_CHECK_EQUAL(challenge_bearing, 7U);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ut::ValidateProductionFamilyProgramSourcesV1(
            manifest, sources, &why),
        why);
    auto shifted = sources;
    const auto found = std::find_if(
        shifted.begin(), shifted.end(),
        [](const auto& source) {
            return source.program.challenge_width != 0;
        });
    BOOST_REQUIRE(found != shifted.end());
    BOOST_REQUIRE_GT(
        found->phase.r0_base_columns.size(), 1U);
    found->phase.r0_base_columns.erase(
        found->phase.r0_base_columns.begin());
    BOOST_CHECK(
        !ut::ValidateProductionFamilyProgramSourcesV1(
            manifest, shifted, &why));
}

BOOST_AUTO_TEST_CASE(
    native_safe_v2_child_rejects_seed_r0_schedule_and_challenge_attacks)
{
    const NativeChildFixture fixture =
        BuildNativeChildFixture();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        attach::VerifyNativeChildProofV1(
            fixture.program, fixture.rows,
            fixture.r0_columns, fixture.seed,
            fixture.proof, &why),
        why);

    // A child proof cannot be transplanted across canonical child seeds.
    BOOST_CHECK(
        !attach::VerifyNativeChildProofV1(
            fixture.program, fixture.rows,
            fixture.r0_columns, Filled(0x5b),
            fixture.proof, &why));

    // The ordered R0 ownership manifest is part of the statement.
    auto shifted_schedule = fixture.r0_columns;
    shifted_schedule[1] = 2;
    BOOST_CHECK(
        !attach::VerifyNativeChildProofV1(
            fixture.program, fixture.rows,
            shifted_schedule, fixture.seed,
            fixture.proof, &why));

    // Mutating the authenticated R0 root changes the derived bytecode
    // challenge and is rejected by the native SAFE verifier.
    auto bad_r0 = fixture.proof;
    bad_r0.batch.groups[0].row_commit.root[0] =
        gf::Add(
            bad_r0.batch.groups[0].row_commit.root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !attach::VerifyNativeChildProofV1(
            fixture.program, fixture.rows,
            fixture.r0_columns, fixture.seed,
            bad_r0, &why));

    // The outer AIR batching challenge is transcript-owned as well.
    auto bad_challenge = fixture.proof;
    bad_challenge.air_constraint_lambda =
        gf::Add(
            bad_challenge.air_constraint_lambda,
            gf::Fp3::One());
    BOOST_CHECK(
        !attach::VerifyNativeChildProofV1(
            fixture.program, fixture.rows,
            fixture.r0_columns, fixture.seed,
            bad_challenge, &why));

    std::vector<unsigned char> proof_bytes;
    BOOST_REQUIRE_GT(
        aq::SerializeAirQuotientSplitRapRowsProof(
            fixture.proof, proof_bytes),
        0U);
    const uint256 identity = Filled(0x61);
    const uint256 proof_root =
        attach::ComputeChildProofRootV1(
            0, identity, proof_bytes);
    BOOST_REQUIRE(!proof_root.IsNull());
    proof_bytes.back() ^= 1U;
    BOOST_CHECK_NE(
        attach::ComputeChildProofRootV1(
            0, identity, proof_bytes),
        proof_root);
}

BOOST_AUTO_TEST_SUITE_END()
