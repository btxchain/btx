// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_coupled_bank_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_header_target.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>
#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>
#include <matmul/matmul_v4_rc_stage3_recursive_parent_air.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <limits>

namespace aq = matmul::v4::rc::air_quotient;
namespace ar = matmul::v4::rc::air_recurse;
namespace fp =
    matmul::v4::rc::recursive_fixedpoint;
namespace gf = matmul::v4::rc::gkr_field;
namespace ha = matmul::v4::rc::stage3_hash_air;
namespace nr = matmul::v4::rc::narrow_recurse;
namespace rc = matmul::v4::rc;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_recursive_fixedpoint_tests)

namespace {

uint256 Seed(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

rc::RCStage3RelationClosureV1
CompleteSyntheticRelationClosure()
{
    rc::RCStage3RelationClosureV1 out;
    out.unified_root_seed = Seed(0x31);
    out.statement_commitment = Seed(0x32);
    out.ctl_proof_bundle_commitment = Seed(0x33);
    const auto& order = rc::RCStage3UnifiedRoleOrder();
    uint16_t global_endpoint = 0;
    for (uint16_t role_ordinal = 0;
         role_ordinal < order.size();
         ++role_ordinal) {
        rc::RCStage3RelationRoleClosure role;
        role.role = order[role_ordinal];
        role.relation_commitment =
            Seed(static_cast<unsigned char>(
                0x40 + role_ordinal));
        role.relation_statement_root =
            Seed(static_cast<unsigned char>(
                0x50 + role_ordinal));
        for (const auto endpoint :
             rc::RequiredRCStage3RelationEndpoints(
                 role.role)) {
            rc::RCStage3RelationEndpointPin pin;
            pin.endpoint = endpoint;
            pin.instance_count =
                uint64_t{1} + global_endpoint;
            pin.manifest_root =
                Seed(static_cast<unsigned char>(
                    0x60 + global_endpoint));
            pin.proof_root =
                Seed(static_cast<unsigned char>(
                    0x70 + global_endpoint));
            pin.semantic_root =
                Seed(static_cast<unsigned char>(
                    0x80 + global_endpoint));
            pin.proof_column_root =
                Seed(static_cast<unsigned char>(
                    0x90 + global_endpoint));
            pin.recursive_child_commitment =
                Seed(static_cast<unsigned char>(
                    0xa0 + global_endpoint));
            role.endpoints.push_back(pin);
            ++global_endpoint;
        }
        role.endpoint_multiproof_root =
            rc::ComputeRCStage3RelationRoleMultiproofRoot(
                role);
        out.roles.push_back(std::move(role));
    }
    out.composition_link_commitment = Seed(0xd1);
    out.final_digest_manifest_root = Seed(0xd2);
    out.final_digest_proof_root = Seed(0xd3);
    out.final_digest_semantic_root = Seed(0xd4);
    out.final_digest_recursive_child_commitment =
        Seed(0xd5);
    out.closure_commitment =
        rc::ComputeRCStage3RelationClosureCommitment(
            out);
    return out;
}

aq::AirConstraintSystem<gf::Fp3> BooleanChildSystem(
    uint32_t n_rows = 2)
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = n_rows;
    cs.n_columns = 1;
    aq::AirConstraint<gf::Fp3> boolean;
    boolean.name = "stage3.fixedpoint.test.boolean";
    boolean.kind = aq::AirKind::kEverywhere;
    boolean.alg_degree = 2;
    boolean.eval =
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Mul(
                cur[0],
                gf::Sub(cur[0], gf::Fp3::One()));
        };
    cs.constraints.push_back(std::move(boolean));
    return cs;
}

struct HonestChild {
    aq::AirConstraintSystem<gf::Fp3> cs;
    fp::AlgAirProof proof;
    uint256 seed;
};

HonestChild BuildHonestChild(
    unsigned char seed_byte,
    uint32_t n_rows = 2)
{
    HonestChild out;
    out.seed = Seed(seed_byte);
    out.cs = BooleanChildSystem(n_rows);
    std::vector<std::vector<gf::Fp3>> columns(
        1, std::vector<gf::Fp3>(
               n_rows, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < n_rows; ++row) {
        columns[0][row] =
            (row & 1U) == 0
            ? gf::Fp3::Zero()
            : gf::Fp3::One();
    }
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            out.cs, columns, out.seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact, proved.note);
    out.proof = proved.proof;
    return out;
}

rc::RCStage3SuccinctProof HeaderTargetStatement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Episode;
    out.public_inputs.height = 23;
    out.public_inputs.n_bits = 0x1d00ffffU;
    out.public_inputs.episode_profile = 2;
    out.public_inputs.transcript_version = rc::ENC_RC_V4;
    out.public_inputs.header_commitment = Seed(0x71);
    out.public_inputs.params_commitment = Seed(0x72);
    out.public_inputs.sigma = Seed(0x73);
    out.public_inputs.episode_digest = Seed(0x74);
    out.public_inputs.target.SetNull();
    out.public_inputs.target.data()[26] = 0xff;
    out.public_inputs.target.data()[27] = 0xff;
    return out;
}

struct HeaderTargetChild {
    HonestChild child;
    rc::constraint_bytecode::Program program;
    rc::constraint_bytecode::ProgramTable table;
};

HeaderTargetChild BuildHeaderTargetChild()
{
    HeaderTargetChild out;
    const auto statement = HeaderTargetStatement();
    rc::RCStage3EpisodeHeaderTargetPin pin;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeHeaderTargetPin(
            statement, pin, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeHeaderTargetConstraintSystem(
            pin, out.child.cs, &why),
        why);
    out.child.cs.preprocessed_pin_ood = true;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeHeaderTargetConstraintProgram(
            pin, out.program, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeHeaderTargetProgramTable(
            pin, out.table, &why),
        why);
    out.child.seed = Seed(0x75);
    std::vector<std::vector<gf::Fp3>> columns(
        out.child.cs.n_columns,
        std::vector<gf::Fp3>(
            out.child.cs.n_rows, gf::Fp3::Zero()));
    for (const auto& [column, values] :
         out.child.cs.preprocessed) {
        columns[column] = values;
    }
    columns[rc::kRCStage3EpisodeHeaderTargetByte] =
        columns[
            rc::kRCStage3EpisodeHeaderTargetExpectedByte];
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            out.child.cs, columns, out.child.seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact, proved.note);
    out.child.proof = proved.proof;
    return out;
}

// g2b (narrow follow-up): a REAL SHA256("abc") compression instance over the
// same selector-pinned fixed-program AIR that already backs the
// CoupledBarrier/CoupledDigest hash kernel bytecode. Its constraint system
// and honest witness are role-independent (the bytecode ProgramTable only
// differs in the committed `role`), so this single child is reused to attach
// the EpisodeTileTree- and EpisodeDigest-committed hash kernel tables via
// AttachConstraintBytecodeInterpreter.
HonestChild BuildHashKernelChild()
{
    HonestChild out;
    const ha::FixedProgram program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramConstraintSystem(
            program, out.cs, &why),
        why);

    // NIST SHA256("abc") test vector padded into one 512-bit block, plus the
    // canonical IV/round-constant externals the fixed program expects.
    static constexpr uint32_t H0[8]{
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
    static constexpr uint32_t K[64]{
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};
    std::vector<uint32_t> external(88, 0);
    external[0] = 0x61626380U; // "abc" plus SHA padding
    external[15] = 24U;        // big-endian bit length
    std::copy(std::begin(H0), std::end(H0), external.begin() + 16);
    std::copy(std::begin(K), std::end(K), external.begin() + 24);
    ha::ProgramWitness witness;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildProgramWitness(
            program, external, witness, &why),
        why);
    std::vector<std::vector<gf::Fp3>> columns;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramAirWitness(
            program, witness, columns, &why),
        why);

    out.seed = Seed(0x76);
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            out.cs, columns, out.seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact, proved.note);
    out.proof = proved.proof;
    return out;
}

struct CoupledBankChild {
    HonestChild child;
    rc::RCStage3CoupledBankDequantPin source_pin;
    fp::NormalizedCoupledBankRowPin row_pin;
    rc::constraint_bytecode::ProgramTable table;
    std::vector<std::vector<gf::Fp3>> columns;
};

CoupledBankChild BuildCoupledBankChild()
{
    CoupledBankChild out;
    constexpr uint32_t n_rows = 2;
    out.columns.assign(
        rc::kRCStage3CoupledBankDequantColumns,
        std::vector<gf::Fp3>(
            n_rows, gf::Fp3::Zero()));
    const uint64_t mantissas[n_rows] = {3, 5};
    const uint64_t scales[n_rows] = {1, 3};
    for (uint32_t row = 0; row < n_rows; ++row) {
        const uint64_t b0 = scales[row] & 1U;
        const uint64_t b1 = (scales[row] >> 1) & 1U;
        const uint64_t factor = uint64_t{1} << scales[row];
        out.columns[
            rc::kRCStage3CoupledBankMantissa][row] =
            gf::Fp3::FromFp(mantissas[row]);
        out.columns[
            rc::kRCStage3CoupledBankRepeatedScale][row] =
            gf::Fp3::FromFp(scales[row]);
        out.columns[
            rc::kRCStage3CoupledBankScaleBit0][row] =
            gf::Fp3::FromFp(b0);
        out.columns[
            rc::kRCStage3CoupledBankScaleBit1][row] =
            gf::Fp3::FromFp(b1);
        out.columns[
            rc::kRCStage3CoupledBankScaleFactor][row] =
            gf::Fp3::FromFp(factor);
        out.columns[
            rc::kRCStage3CoupledBankOutput][row] =
            gf::Fp3::FromFp(mantissas[row] * factor);
    }

    rc::RCStage3CoupledBankDequantPin& pin =
        out.source_pin;
    pin.statement_commitment = Seed(0x81);
    pin.shape_commitment = Seed(0x82);
    pin.sigma = Seed(0x83);
    pin.logical_rows = n_rows;
    pin.n_rows = n_rows;
    pin.n_coeffs = n_rows;
    auto root_columns = out.columns;
    root_columns.emplace_back(
        n_rows, gf::Fp3::Zero());
    aq::AirConstraintSystem<gf::Fp3> row_shape;
    row_shape.n_rows = n_rows;
    row_shape.n_columns = root_columns.size();
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            row_shape, root_columns,
            {0, 1, 2, 3, 4, 5});
    BOOST_REQUIRE(r0.valid);
    pin.r0_row_group_root =
        r0.base_row_commitment;
    pin.pin_commitment =
        rc::ComputeRCStage3CoupledBankDequantPinCommitment(
            pin);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        !pin.pin_commitment.IsNull(), "dequant test pin");
    BOOST_REQUIRE_MESSAGE(
        fp::BuildNormalizedCoupledBankConstraintSystem(
            pin, out.child.cs, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankDequantProgramTable(
            pin, out.table, &why),
        why);
    out.child.seed =
        rc::ComputeRCStage3CoupledBankDequantSeed(pin);
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            out.child.cs, out.columns, out.child.seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact, proved.note);
    out.child.proof = proved.proof;
    const auto streamed =
        aq::AirQuotientProveRows(
            out.child.cs, out.columns,
            out.child.seed, {});
    BOOST_REQUIRE_MESSAGE(
        streamed.ok && streamed.division_exact,
        streamed.note);
    std::string stream_verify_why;
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRows(
            out.child.cs, streamed.proof,
            out.child.seed, &stream_verify_why),
        stream_verify_why);
    std::vector<unsigned char> dense_batch;
    std::vector<unsigned char> streamed_batch;
    BOOST_REQUIRE_NE(
        rc::SerializeFri3AlgBatchProof(
            out.child.proof.batch, dense_batch),
        0U);
    BOOST_REQUIRE_NE(
        rc::SerializeFri3AlgBatchProof(
            streamed.proof.batch, streamed_batch),
        0U);
    BOOST_CHECK(dense_batch == streamed_batch);
    BOOST_REQUIRE_EQUAL(
        out.child.proof.next_openings.size(),
        streamed.proof.next_openings.size());
    for (size_t query = 0;
         query < out.child.proof.next_openings.size();
         ++query) {
        const auto& dense_paths =
            out.child.proof.next_openings[query];
        const auto& streamed_paths =
            streamed.proof.next_openings[query];
        BOOST_REQUIRE_EQUAL(
            dense_paths.size(), streamed_paths.size());
        for (size_t path = 0;
             path < dense_paths.size(); ++path) {
            BOOST_CHECK_EQUAL(
                dense_paths[path].index,
                streamed_paths[path].index);
            BOOST_REQUIRE_EQUAL(
                dense_paths[path].values.size(),
                streamed_paths[path].values.size());
            for (size_t cell = 0;
                 cell < dense_paths[path].values.size();
                 ++cell) {
                BOOST_CHECK(gf::Eq(
                    dense_paths[path].values[cell],
                    streamed_paths[path].values[cell]));
            }
            BOOST_CHECK(
                dense_paths[path].siblings ==
                streamed_paths[path].siblings);
        }
    }
    BOOST_CHECK(
        out.child.proof.trace_commit ==
        streamed.proof.trace_commit);
    const aq::AirQuotientSpillAudit spill =
        aq::AuditAirQuotientSpillFp3(
            out.child.cs, out.columns,
            out.child.seed, 2,
            aq::AirExternalStoreBackend::
                kAnonymousTempFile);
    BOOST_REQUIRE_MESSAGE(spill.valid, spill.note);
    BOOST_CHECK(spill.all_lde_columns_spilled);
    BOOST_CHECK(spill.all_tiles_reloaded);
    BOOST_CHECK(spill.byte_canonical_roundtrip);
    BOOST_CHECK_EQUAL(spill.store_resident_cells, 0U);
    BOOST_REQUIRE_MESSAGE(
        fp::BuildNormalizedCoupledBankRowPin(
            pin, out.child.proof, out.row_pin, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        fp::VerifyNormalizedCoupledBankProof(
            pin, out.row_pin, out.child.proof,
            out.child.seed, &why),
        why);
    return out;
}

rc::RCStage3CtlParticipantSpec CtlParticipant(
    rc::RCStage3RelationRole role,
    const rc::RCStage3CtlSchedule& schedule)
{
    uint64_t sends = 0;
    uint64_t receives = 0;
    for (const auto& event : schedule.events) {
        sends += event.multiplicity == 1 ? 1 : 0;
        receives += event.multiplicity == -1 ? 1 : 0;
    }
    return {
        role,
        schedule.events.size(),
        sends,
        receives,
        rc::CommitRCStage3CtlSchedule(schedule)};
}

struct CanonicalBankCtl {
    rc::RCStage3CtlManifest manifest;
    std::vector<rc::RCStage3CtlChildPin> pins;
    std::vector<rc::RCStage3CtlSchedule> schedules;
    rc::RCStage3CtlAirProof bank_proof;
    size_t bank_index{0};
};

CanonicalBankCtl BuildCanonicalBankCtl(
    const rc::RCStage3CoupledBankDequantPin&
        bank_source)
{
    CanonicalBankCtl out;
    const auto& order = rc::RCStage3UnifiedRoleOrder();
    out.manifest.bus_id = 0x43424e4bU;
    out.manifest.transcript_seed = Seed(0xa0);
    out.pins.resize(order.size());
    out.schedules.resize(order.size());
    std::vector<std::vector<gf::Fp3>> values(
        order.size());
    const gf::Fp3 filler =
        gf::Fp3::FromFp(gf::FromU64(19));
    for (size_t index = 0;
         index < order.size(); ++index) {
        if (order[index] ==
                rc::RCStage3RelationRole::
                    CoupledBank) {
            out.bank_index = index;
            std::string export_why;
            BOOST_REQUIRE_MESSAGE(
                fp::BuildNormalizedCoupledBankCtlRootScheduleV1(
                    bank_source,
                    out.schedules[index],
                    values[index],
                    &export_why),
                export_why);
        } else {
            out.schedules[index].events = {
                {91, 7,
                 static_cast<uint32_t>(index + 1),
                 1},
                {91, 7,
                 static_cast<uint32_t>(index + 1),
                 -1},
            };
            values[index] = {filler, filler};
        }
        out.manifest.participants.push_back(
            CtlParticipant(
                order[index],
                out.schedules[index]));
        auto& pin = out.pins[index];
        const auto& participant =
            out.manifest.participants[index];
        pin.role = participant.role;
        pin.bus_id = out.manifest.bus_id;
        pin.event_count = participant.event_count;
        pin.send_count = participant.send_count;
        pin.receive_count = participant.receive_count;
        pin.schedule_commitment =
            participant.schedule_commitment;
        pin.trace_commitment =
            rc::ComputeRCStage3CtlPrechallengeTraceCommitment(
                out.schedules[index],
                values[index]);
        BOOST_REQUIRE(!pin.trace_commitment.IsNull());
    }
    rc::RCStage3CtlChallenges challenges;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::DeriveRCStage3CtlChallenges(
            out.manifest, out.pins,
            challenges, &why),
        why);
    const uint256 challenge_commitment =
        rc::CommitRCStage3CtlChallenges(challenges);
    BOOST_REQUIRE(!challenge_commitment.IsNull());
    for (size_t index = 0;
         index < order.size(); ++index) {
        const auto witness =
            rc::BuildRCStage3CtlWitness(
                out.schedules[index],
                values[index],
                challenges);
        BOOST_REQUIRE_MESSAGE(
            witness.ok, witness.note);
        auto& pin = out.pins[index];
        pin.terminal = witness.terminal;
        pin.challenge_commitment =
            challenge_commitment;
        pin.auxiliary_commitment =
            Seed(static_cast<unsigned char>(
                0xb0 + index));
        if (index == out.bank_index) {
            const uint256 proof_seed =
                rc::ComputeRCStage3CtlAirSeed(
                    out.manifest, pin);
            BOOST_REQUIRE(!proof_seed.IsNull());
            const auto cs =
                rc::BuildRCStage3CtlConstraintSystem(
                    {out.schedules[index],
                     challenges,
                     witness.terminal});
            const auto proved =
                aq::AirQuotientProve<gf::Fp3>(
                    cs, witness.columns,
                    proof_seed);
            BOOST_REQUIRE_MESSAGE(
                proved.ok &&
                    proved.division_exact,
                proved.note);
            out.bank_proof = proved.proof;
            pin.auxiliary_commitment =
                rc::ComputeRCStage3CtlAuxiliaryCommitment(
                    out.bank_proof);
            BOOST_REQUIRE(
                !pin.auxiliary_commitment.IsNull());
        }
    }
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CtlPublicPinComposition(
            out.manifest, out.pins, &why),
        why);
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    complete_screen_selects_parallel_binary_quadratic)
{
    const auto scenarios =
        fp::AssessCompleteFixedPointScenarios();
    BOOST_REQUIRE_EQUAL(scenarios.size(), 9U);
    uint32_t selected = 0;
    for (const auto& scenario : scenarios) {
        BOOST_CHECK(scenario.charges_current_next_trace);
        if (scenario.selected_v1_topology) {
            ++selected;
            BOOST_CHECK(
                scenario.poseidon_strategy ==
                nr::PoseidonLaneStrategy::
                    DecomposedX2X4X6);
            BOOST_CHECK(
                scenario.child_packing ==
                nr::ChildPacking::ParallelLanes);
            BOOST_CHECK_EQUAL(scenario.logical_children, 2U);
            BOOST_CHECK_EQUAL(
                scenario.repeated_lanes_per_child, 2U);
            BOOST_CHECK_EQUAL(scenario.verifier_lanes, 4U);
            BOOST_CHECK_EQUAL(scenario.physical_lanes, 4U);
            BOOST_CHECK(scenario.width_fixed_point);
            BOOST_CHECK(scenario.trace_fixed_point);
            BOOST_CHECK(
                scenario.backend_shape_supported);
            BOOST_CHECK_EQUAL(
                scenario.leaf.parent_width, 2184U);
            BOOST_CHECK_EQUAL(
                scenario.level1.parent_width, 2184U);
            BOOST_CHECK_EQUAL(
                scenario.level2.parent_width, 2184U);
            BOOST_CHECK_LE(
                scenario.level1.parent_lde,
                uint32_t{1} << rc::kRCFriMaxLdeLog2);
            BOOST_CHECK_LE(
                scenario.level2.parent_lde,
                uint32_t{1} << rc::kRCFriMaxLdeLog2);
            BOOST_CHECK(
                scenario.executable_hash_opening_air);
            BOOST_CHECK(scenario.executable_scalar_air);
            BOOST_CHECK(!scenario.executable_memory_bus);
            BOOST_CHECK(!scenario.complete_recursive_parent);
            BOOST_TEST_MESSAGE(
                "complete fixed point: leaf(active="
                << scenario.leaf.active_rows
                << ",trace=" << scenario.leaf.trace_rows
                << ",lde=" << scenario.leaf.parent_lde
                << ") level1(active="
                << scenario.level1.active_rows
                << ",trace="
                << scenario.level1.trace_rows
                << ",lde=" << scenario.level1.parent_lde
                << ") level2(active="
                << scenario.level2.active_rows
                << ",trace="
                << scenario.level2.trace_rows
                << ",lde=" << scenario.level2.parent_lde
                << ")");
        }
    }
    BOOST_CHECK_EQUAL(selected, 1U);
    static_assert(
        !fp::kCompleteRecursiveFixedPointExecutable);
    static_assert(
        !fp::kRecursiveFixedPointConsensusAuthority);
}

BOOST_AUTO_TEST_CASE(
    four_v5_lanes_require_full_parallel_packing)
{
    const auto selected =
        fp::SelectCompleteFixedPointV1();
    BOOST_REQUIRE(selected.selected_v1_topology);
    BOOST_CHECK_GT(selected.level1.next_row_rows, 0U);
    BOOST_CHECK_GT(
        selected.level1.trace_binding_rows, 0U);

    uint32_t slower_layouts = 0;
    for (const auto& scenario :
         fp::AssessCompleteFixedPointScenarios()) {
        if (scenario.poseidon_strategy ==
                nr::PoseidonLaneStrategy::
                    DecomposedX2X4X6 &&
            scenario.physical_lanes < 4) {
            ++slower_layouts;
            BOOST_CHECK(!scenario.selected_v1_topology);
            BOOST_CHECK(!scenario.backend_shape_supported);
            BOOST_CHECK(
                !scenario.level1.lde_supported ||
                !scenario.level2.lde_supported);
            BOOST_TEST_MESSAGE(
                "complete slower-lane comparison: physical_lanes="
                << scenario.physical_lanes
                << " level1(active="
                << scenario.level1.active_rows
                << ",trace=" << scenario.level1.trace_rows
                << ",lde=" << scenario.level1.parent_lde
                << ",lde_ok="
                << scenario.level1.lde_supported
                << ") level2(active="
                << scenario.level2.active_rows
                << ",trace=" << scenario.level2.trace_rows
                << ",lde=" << scenario.level2.parent_lde
                << ",lde_ok="
                << scenario.level2.lde_supported << ")");
        }
    }
    BOOST_CHECK_EQUAL(slower_layouts, 2U);
}

BOOST_AUTO_TEST_CASE(
    proof_derived_hash_openings_execute_all_path_families)
{
    const HonestChild child = BuildHonestChild(0x41);

    fp::HashOpeningWitness witness =
        fp::BuildHashOpeningWitness(
            child.cs, child.proof, child.seed);
    BOOST_REQUIRE_MESSAGE(witness.valid, witness.note);
    BOOST_CHECK(witness.proof_derived);
    BOOST_CHECK(witness.native_child_accepted);
    BOOST_CHECK_EQUAL(witness.violations, 0U);
    BOOST_CHECK(
        witness.program.current_row_opening);
    BOOST_CHECK(witness.program.next_row_opening);
    BOOST_CHECK(witness.program.trace_root_opening);
    BOOST_CHECK(witness.program.every_fold_opening);

    aq::AirConstraintSystem<gf::Fp3> hash_cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        fp::BuildHashOpeningConstraintSystem(
            witness.program, hash_cs, &why),
        why);
    const auto layout =
        fp::CanonicalHashOpeningLayout();
    BOOST_CHECK_EQUAL(hash_cs.n_columns, layout.End());
    BOOST_CHECK_LT(hash_cs.n_columns, 1024U);
    BOOST_CHECK_EQUAL(
        hash_cs.n_rows, witness.program.trace_rows);
    BOOST_CHECK_GE(hash_cs.constraints.size(), 500U);

    auto bad_x6 = witness.columns;
    bad_x6[layout.x6_base][0] =
        gf::Add(
            bad_x6[layout.x6_base][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            hash_cs, bad_x6),
        0U);

    auto bad_absorb = witness.columns;
    bad_absorb[layout.absorbed_pin_base][0] =
        gf::Add(
            bad_absorb[layout.absorbed_pin_base][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            hash_cs, bad_absorb),
        0U);

    uint32_t merkle_row = 0;
    while (merkle_row < witness.program.active_rows &&
           witness.program.rows[merkle_row].kind !=
               fp::HashRowKind::MerkleCompress) {
        ++merkle_row;
    }
    BOOST_REQUIRE_LT(
        merkle_row, witness.program.active_rows);
    auto bad_route = witness.columns;
    const uint32_t input =
        layout.perm.InputCol(
            witness.program.rows[merkle_row].direction
                ? rc::alg_hash::kAlgHashDigestLen
                : 0);
    bad_route[input][merkle_row] =
        gf::Add(
            bad_route[input][merkle_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            hash_cs, bad_route),
        0U);

    auto omitted = witness.program;
    omitted.rows.erase(omitted.rows.begin() + 1);
    BOOST_CHECK(
        !fp::BuildHashOpeningConstraintSystem(
            omitted, hash_cs, &why));

    BOOST_TEST_MESSAGE(
        "proof-derived hash V_CS: active_rows="
        << witness.program.active_rows
        << " trace_rows=" << witness.program.trace_rows
        << " columns=" << layout.End()
        << " constraints=" << hash_cs.constraints.size());
}

BOOST_AUTO_TEST_CASE(
    fold_hash_scalar_join_uses_dual_rational_identity)
{
    const HonestChild child = BuildHonestChild(0x42);
    fp::FoldBusComposition joined =
        fp::BuildFoldBusComposition(
            child.cs, child.proof, child.seed);
    BOOST_REQUIRE_MESSAGE(joined.valid, joined.note);
    BOOST_CHECK(joined.hash.proof_derived);
    BOOST_CHECK(joined.direct_hash_alias);
    BOOST_CHECK(joined.commit_then_challenge);
    BOOST_CHECK(joined.dual_logup_terminal);
    BOOST_CHECK(joined.fold_equations);
    BOOST_CHECK(
        joined.fold_chain_and_final_equations);
    BOOST_CHECK(joined.initial_deep_identity);
    BOOST_CHECK_GT(joined.fold_pairs, 0U);
    BOOST_CHECK_EQUAL(joined.violations, 0U);
    BOOST_CHECK(!joined.deep_per_point_transition_join);
    BOOST_CHECK(!joined.prechallenge_commitment.IsNull());
    BOOST_CHECK_LT(joined.combined.n_columns, 1024U);

    uint32_t receive_row = 0;
    while (receive_row < joined.combined.n_rows &&
           gf::IsZero(
               joined.columns[
                   joined.bus.ReceiveEven(0)][receive_row])) {
        ++receive_row;
    }
    BOOST_REQUIRE_LT(
        receive_row, joined.combined.n_rows);

    // Changing the scalar operand cannot preserve both the literal receiver
    // alias and the rational multiset identity.
    auto bad_consumer = joined.columns;
    bad_consumer[joined.bus.consumer_even][receive_row] =
        gf::Add(
            bad_consumer[joined.bus.consumer_even][receive_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined, bad_consumer),
        0U);

    // Address substitution is rejected even if the value is unchanged.
    auto bad_address = joined.columns;
    bad_address[joined.bus.Address(0)][receive_row] =
        gf::Add(
            bad_address[joined.bus.Address(0)][receive_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined, bad_address),
        0U);

    // An authenticated producer leaf cannot be detached from the bus value.
    uint32_t send_row = 0;
    while (send_row < joined.combined.n_rows &&
           gf::IsZero(
               joined.columns[
                   joined.bus.Send(0)][send_row])) {
        ++send_row;
    }
    BOOST_REQUIRE_LT(send_row, joined.combined.n_rows);
    auto bad_producer = joined.columns;
    bad_producer[joined.bus.Value(0)][send_row] =
        gf::Add(
            bad_producer[joined.bus.Value(0)][send_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined, bad_producer),
        0U);

    uint32_t deep_row = 0;
    while (deep_row < joined.combined.n_rows &&
           gf::IsZero(
               joined.columns[
                   joined.deep.identity_selector][deep_row])) {
        ++deep_row;
    }
    BOOST_REQUIRE_LT(deep_row, joined.combined.n_rows);
    auto bad_deep_running = joined.columns;
    bad_deep_running[joined.deep.running][deep_row] =
        gf::Add(
            bad_deep_running[
                joined.deep.running][deep_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined, bad_deep_running),
        0U);

    BOOST_TEST_MESSAGE(
        "fold dual-LogUp join: pairs="
        << joined.fold_pairs
        << " rows=" << joined.combined.n_rows
        << " columns=" << joined.combined.n_columns
        << " constraints="
        << joined.combined.constraints.size());
}

BOOST_AUTO_TEST_CASE(
    deep_fold_chain_and_final_are_same_trace_constrained)
{
    const HonestChild child =
        BuildHonestChild(0x43, 4);
    fp::FoldBusComposition joined =
        fp::BuildFoldBusComposition(
            child.cs, child.proof, child.seed);
    BOOST_REQUIRE_MESSAGE(joined.valid, joined.note);
    BOOST_CHECK(joined.direct_hash_alias);
    BOOST_CHECK(joined.dual_logup_terminal);
    BOOST_CHECK(joined.fold_equations);
    BOOST_CHECK(
        joined.fold_chain_and_final_equations);
    BOOST_CHECK_GT(joined.fold_chain_pairs, 0U);
    BOOST_CHECK_EQUAL(
        joined.fold_final_rows,
        joined.hash.program.public_inputs.
            query_index.size());
    BOOST_CHECK_EQUAL(joined.violations, 0U);
    BOOST_CHECK_LT(
        joined.combined.n_columns, 1024U);

    uint32_t receive_row = 0;
    while (receive_row < joined.combined.n_rows &&
           gf::IsZero(
               joined.columns[
                   joined.chain.receive][receive_row])) {
        ++receive_row;
    }
    BOOST_REQUIRE_LT(
        receive_row, joined.combined.n_rows);
    auto bad_selected_leaf = joined.columns;
    bad_selected_leaf[joined.chain.value][receive_row] =
        gf::Add(
            bad_selected_leaf[
                joined.chain.value][receive_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined, bad_selected_leaf),
        0U);

    uint32_t send_row = 0;
    while (send_row < joined.combined.n_rows &&
           gf::IsZero(
               joined.columns[
                   joined.chain.send][send_row])) {
        ++send_row;
    }
    BOOST_REQUIRE_LT(send_row, joined.combined.n_rows);
    auto bad_folded = joined.columns;
    bad_folded[joined.chain.value][send_row] =
        gf::Add(
            bad_folded[joined.chain.value][send_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined, bad_folded),
        0U);

    auto bad_address = joined.columns;
    bad_address[joined.chain.address][receive_row] =
        gf::Add(
            bad_address[
                joined.chain.address][receive_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined, bad_address),
        0U);

    uint32_t final_row = 0;
    while (final_row < joined.combined.n_rows &&
           gf::IsZero(
               joined.columns[
                   joined.chain.final_selector][final_row])) {
        ++final_row;
    }
    BOOST_REQUIRE_LT(final_row, joined.combined.n_rows);
    auto bad_final = joined.columns;
    bad_final[joined.bus.folded][final_row] =
        gf::Add(
            bad_final[joined.bus.folded][final_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined, bad_final),
        0U);

    BOOST_TEST_MESSAGE(
        "vertical DEEP fold chain: pairs="
        << joined.fold_chain_pairs
        << " rows=" << joined.combined.n_rows
        << " cols=" << joined.combined.n_columns
        << " constraints="
        << joined.combined.constraints.size());
}

BOOST_AUTO_TEST_CASE(
    episode_digest_bytecode_uses_authenticated_vertical_memory)
{
    const HeaderTargetChild migrated =
        BuildHeaderTargetChild();
    std::vector<unsigned char> encoded;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::constraint_bytecode::SerializeProgram(
            migrated.program, encoded, &why),
        why);
    rc::constraint_bytecode::Program decoded;
    BOOST_REQUIRE_MESSAGE(
        rc::constraint_bytecode::DeserializeProgram(
            encoded, decoded, &why),
        why);
    BOOST_CHECK(decoded == migrated.program);
    BOOST_CHECK(
        rc::constraint_bytecode::CommitProgram(decoded) ==
        rc::constraint_bytecode::CommitProgram(
            migrated.program));

    auto malformed = encoded;
    BOOST_REQUIRE_GT(malformed.size(), 27U);
    malformed[27] = 0xff;
    BOOST_CHECK(
        !rc::constraint_bytecode::DeserializeProgram(
            malformed, decoded, &why));
    std::vector<unsigned char> encoded_table;
    BOOST_REQUIRE_MESSAGE(
        rc::constraint_bytecode::SerializeProgramTable(
            migrated.table, encoded_table, &why),
        why);
    rc::constraint_bytecode::ProgramTable decoded_table;
    BOOST_REQUIRE_MESSAGE(
        rc::constraint_bytecode::DeserializeProgramTable(
            encoded_table, decoded_table, &why),
        why);
    BOOST_CHECK(decoded_table == migrated.table);
    BOOST_CHECK_EQUAL(
        migrated.table.programs.size(),
        migrated.child.cs.constraints.size());
    BOOST_CHECK_EQUAL(
        migrated.table.programs.front().constraint_ordinal,
        0U);
    BOOST_CHECK(
        migrated.table.programs.front().kind ==
        migrated.child.cs.constraints.front().kind);
    BOOST_CHECK_EQUAL(
        migrated.table.programs.front().declared_degree,
        migrated.child.cs.constraints.front().alg_degree);
    BOOST_CHECK(
        rc::constraint_bytecode::CommitProgramTable(
            decoded_table) ==
        rc::constraint_bytecode::CommitProgramTable(
            migrated.table));

    const auto inventory =
        rc::constraint_bytecode::
            CurrentRoleMigrationInventory();
    BOOST_REQUIRE_EQUAL(inventory.size(), 14U);
    uint32_t partial = 0;
    uint32_t not_started = 0;
    for (const auto& role : inventory) {
        if (role.state ==
            rc::constraint_bytecode::MigrationState::Partial) {
            ++partial;
            BOOST_CHECK_GE(
                role.migrated_constraint_builders, 1U);
            BOOST_CHECK(role.opaque_callbacks_remain);
        } else if (
            role.state ==
            rc::constraint_bytecode::
                MigrationState::NotStarted) {
            ++not_started;
        }
    }
    BOOST_CHECK_EQUAL(partial, 14U);
    BOOST_CHECK_EQUAL(not_started, 0U);

    fp::FoldBusComposition joined =
        fp::BuildFoldBusComposition(
            migrated.child.cs,
            migrated.child.proof,
            migrated.child.seed);
    BOOST_REQUIRE_MESSAGE(joined.valid, joined.note);
    const uint32_t before_columns =
        joined.combined.n_columns;
    fp::BytecodeInterpreterAttachment interpreter =
        fp::AttachConstraintBytecodeInterpreter(
            joined, migrated.table);
    BOOST_REQUIRE_MESSAGE(
        interpreter.valid, interpreter.note);
    BOOST_CHECK(interpreter.canonical_program);
    BOOST_CHECK(
        interpreter.authenticated_row_memory_bus);
    BOOST_CHECK(interpreter.dual_logup_terminal);
    BOOST_CHECK(!interpreter.result_zero_constrained);
    BOOST_CHECK(interpreter.quotient_opening_equality);
    BOOST_CHECK(
        joined.deep_per_point_transition_join);
    BOOST_CHECK_GT(
        interpreter.authenticated_source_coordinates,
        0U);
    BOOST_CHECK_EQUAL(
        interpreter.instruction_rows,
        joined.hash.program.public_inputs.
                query_index.size() *
            migrated.program.instructions.size());
    BOOST_CHECK_EQUAL(interpreter.violations, 0U);
    BOOST_CHECK_EQUAL(
        joined.combined.n_columns,
        before_columns + 65U);

    uint32_t source_row = 0;
    while (source_row < joined.combined.n_rows &&
           gf::IsZero(
               joined.columns[
                   interpreter.layout.RowKind(0)]
                             [source_row])) {
        ++source_row;
    }
    BOOST_REQUIRE_LT(
        source_row, joined.combined.n_rows);
    auto bad_source = joined.columns;
    bad_source[
        interpreter.layout.Value(0)][source_row] =
        gf::Add(
            bad_source[
                interpreter.layout.Value(0)][source_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined, bad_source),
        0U);

    uint32_t sub_row = 0;
    while (sub_row < joined.combined.n_rows &&
           gf::IsZero(
               joined.columns[
                   interpreter.layout.RowKind(6)]
                             [sub_row])) {
        ++sub_row;
    }
    BOOST_REQUIRE_LT(sub_row, joined.combined.n_rows);
    auto bad_operand = joined.columns;
    bad_operand[
        interpreter.layout.Value(0)][sub_row] =
        gf::Add(
            bad_operand[
                interpreter.layout.Value(0)][sub_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined, bad_operand),
        0U);

    uint32_t quotient_row = 0;
    while (quotient_row < joined.combined.n_rows &&
           gf::IsZero(
               joined.columns[
                   interpreter.layout.RowKind(8)]
                             [quotient_row])) {
        ++quotient_row;
    }
    BOOST_REQUIRE_LT(
        quotient_row, joined.combined.n_rows);
    auto bad_quotient = joined.columns;
    bad_quotient[
        interpreter.layout.Value(3)][quotient_row] =
        gf::Add(
            bad_quotient[
                interpreter.layout.Value(3)]
                       [quotient_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined, bad_quotient),
        0U);

    BOOST_TEST_MESSAGE(
        "registered EpisodeDigest bytecode: rows="
        << joined.combined.n_rows
        << " cols=" << joined.combined.n_columns
        << " constraints="
        << joined.combined.constraints.size()
        << " authenticated_coords="
        << interpreter.authenticated_source_coordinates
        << " instruction_rows="
        << interpreter.instruction_rows);
}

BOOST_AUTO_TEST_CASE(
    coupled_bank_full_program_table_executes_in_normalized_parent)
{
    const CoupledBankChild migrated =
        BuildCoupledBankChild();
    BOOST_REQUIRE_EQUAL(
        migrated.table.programs.size(), 5U);
    BOOST_REQUIRE_EQUAL(
        migrated.table.programs.size(),
        migrated.child.cs.constraints.size());
    uint32_t instruction_count = 0;
    for (uint32_t ordinal = 0;
         ordinal < migrated.table.programs.size();
         ++ordinal) {
        const auto& program =
            migrated.table.programs[ordinal];
        BOOST_CHECK_EQUAL(
            program.constraint_ordinal, ordinal);
        BOOST_CHECK(
            program.kind ==
            migrated.child.cs.constraints[ordinal].kind);
        BOOST_CHECK_EQUAL(
            program.declared_degree,
            migrated.child.cs.constraints[ordinal].alg_degree);
        instruction_count +=
            static_cast<uint32_t>(
                program.instructions.size());
        for (uint32_t row = 0;
             row < migrated.child.cs.n_rows; ++row) {
            std::vector<gf::Fp3> current(
                migrated.child.cs.n_columns);
            std::vector<gf::Fp3> next(
                migrated.child.cs.n_columns);
            for (uint32_t column = 0;
                 column < migrated.child.cs.n_columns;
                 ++column) {
                current[column] =
                    migrated.columns[column][row];
                next[column] =
                    migrated.columns[column][
                        (row + 1) %
                        migrated.child.cs.n_rows];
            }
            gf::Fp3 result = gf::Fp3::One();
            std::string why;
            BOOST_REQUIRE_MESSAGE(
                rc::constraint_bytecode::EvaluateProgram(
                    program, current, next, result,
                    &why),
                why);
            BOOST_CHECK(gf::IsZero(result));
        }
    }
    // Minimal faithful SSA cost of the five canonical dequant programs over the
    // {Current,Constant,Add,Sub,Mul} opcode set: two booleanity residuals
    // e*(e-1) at 4 each (8), the scale-code residual s-(e0+2e1) at 7, the
    // scale-factor residual f-(1+e0)(1+3e1) at 11, and the dequant residual
    // out-mu*f at 5 -> 31. Every program evaluates to zero on the honest witness
    // above, so 31 is the true post-migration count; the earlier 32 was stale.
    BOOST_CHECK_EQUAL(instruction_count, 31U);

    fp::FoldBusComposition joined =
        fp::BuildFoldBusComposition(
            migrated.child.cs,
            migrated.child.proof,
            migrated.child.seed);
    BOOST_REQUIRE_MESSAGE(joined.valid, joined.note);
    fp::BytecodeInterpreterAttachment interpreter =
        fp::AttachConstraintBytecodeInterpreter(
            joined, migrated.table);
    BOOST_REQUIRE_MESSAGE(
        interpreter.valid, interpreter.note);
    BOOST_CHECK(interpreter.canonical_program);
    BOOST_CHECK(
        interpreter.authenticated_row_memory_bus);
    BOOST_CHECK(interpreter.dual_logup_terminal);
    BOOST_CHECK(interpreter.quotient_opening_equality);
    BOOST_CHECK(
        interpreter.same_trace_relation_cell_logup_export);
    BOOST_CHECK(
        !interpreter.role_semantic_root_terminal_equality);
    BOOST_CHECK(
        joined.deep_per_point_transition_join);
    BOOST_CHECK_EQUAL(interpreter.violations, 0U);
    BOOST_CHECK_EQUAL(
        interpreter.instruction_rows,
        migrated.child.proof.batch.queries.size() *
            instruction_count);
    BOOST_CHECK_EQUAL(joined.combined.n_rows, 8192U);
    BOOST_CHECK_EQUAL(joined.combined.n_columns, 640U);

    const fp::NormalizedParentProofPreflight preflight =
        fp::AssessNormalizedParentProofPreflight(
            joined.combined);
    BOOST_REQUIRE_MESSAGE(preflight.valid, preflight.note);
    BOOST_CHECK_EQUAL(preflight.trace_rows, 8192U);
    BOOST_CHECK_EQUAL(preflight.trace_columns, 640U);
    BOOST_CHECK_EQUAL(
        preflight.constraints,
        joined.combined.constraints.size());
    BOOST_CHECK_EQUAL(preflight.max_alg_degree, 4U);
    BOOST_CHECK_EQUAL(
        preflight.max_composed_degree, 32765U);
    BOOST_CHECK_EQUAL(preflight.quotient_len, 24574U);
    BOOST_CHECK_EQUAL(preflight.composition_rows, 32768U);
    BOOST_CHECK_EQUAL(preflight.n_coeffs, 32768U);
    BOOST_CHECK_EQUAL(preflight.n_lde, 524288U);
    BOOST_CHECK_EQUAL(preflight.queries, 192U);
    BOOST_CHECK_EQUAL(
        preflight.raw_trace_bytes, 125829120U);
    BOOST_CHECK_EQUAL(
        preflight.minimum_batch_row_value_bytes,
        2953728U);
    BOOST_CHECK_EQUAL(
        preflight.minimum_next_row_value_bytes,
        2953728U);
    BOOST_CHECK_EQUAL(
        preflight.minimum_total_row_value_bytes,
        5907456U);
    BOOST_CHECK_EQUAL(
        preflight.current_batch_lde_bytes,
        UINT64_C(8065646592));
    BOOST_CHECK(preflight.degree_supported);
    BOOST_CHECK(preflight.lde_supported);
    BOOST_CHECK(preflight.backend_columns_supported);
    BOOST_CHECK(
        preflight.batch_codec_lower_bound_supported);
    BOOST_CHECK(preflight.spill_audit_available);
    BOOST_CHECK(
        preflight.spill_audit_materializes_dense_lde);
    BOOST_CHECK(
        preflight.two_pass_row_commit_executable);
    BOOST_CHECK(
        preflight.bounded_row_streaming_byte_identical);
    BOOST_CHECK(
        !preflight.external_store_quotient_prover);
    BOOST_CHECK(
        !preflight.streamed_row_commit_callback);
    BOOST_CHECK(
        !preflight.safe_to_execute_current_prover);
    BOOST_CHECK(
        !preflight.missing_streaming_callback.empty());

    // The previous complete EpisodeDigest attachment is a real 32,768-row,
    // 640-column normalized parent. Apply the same live constraint inventory
    // at that production-fixed-point row shape without allocating its trace.
    auto production_shape_cs = joined.combined;
    production_shape_cs.n_rows = 32768;
    const fp::NormalizedParentProofPreflight
        production_preflight =
            fp::AssessNormalizedParentProofPreflight(
                production_shape_cs);
    BOOST_REQUIRE_MESSAGE(
        production_preflight.valid,
        production_preflight.note);
    BOOST_CHECK_EQUAL(
        production_preflight.trace_rows, 32768U);
    BOOST_CHECK_EQUAL(
        production_preflight.trace_columns, 640U);
    BOOST_CHECK_EQUAL(
        production_preflight.max_composed_degree,
        131069U);
    BOOST_CHECK_EQUAL(
        production_preflight.quotient_len, 98302U);
    BOOST_CHECK_EQUAL(
        production_preflight.composition_rows, 131072U);
    BOOST_CHECK_EQUAL(
        production_preflight.n_coeffs, 131072U);
    BOOST_CHECK_EQUAL(
        production_preflight.n_lde, 2097152U);
    BOOST_CHECK_EQUAL(
        production_preflight.raw_trace_bytes,
        503316480U);
    BOOST_CHECK_EQUAL(
        production_preflight.minimum_total_row_value_bytes,
        5907456U);
    BOOST_CHECK_EQUAL(
        production_preflight.current_batch_lde_bytes,
        UINT64_C(32262586368));
    BOOST_CHECK(
        !production_preflight.safe_to_execute_current_prover);

    uint32_t multiply_row = 0;
    while (multiply_row < joined.combined.n_rows &&
           gf::IsZero(
               joined.columns[
                   interpreter.layout.RowKind(7)]
                             [multiply_row])) {
        ++multiply_row;
    }
    BOOST_REQUIRE_LT(
        multiply_row, joined.combined.n_rows);
    auto bad_multiply = joined.columns;
    bad_multiply[
        interpreter.layout.Value(7)][multiply_row] =
        gf::Add(
            bad_multiply[
                interpreter.layout.Value(7)]
                       [multiply_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined, bad_multiply),
        0U);

    BOOST_TEST_MESSAGE(
        "registered CoupledBank bytecode: programs="
        << migrated.table.programs.size()
        << " instruction_rows="
        << interpreter.instruction_rows
        << " rows=" << joined.combined.n_rows
        << " cols=" << joined.combined.n_columns
        << " constraints="
        << joined.combined.constraints.size()
        << " quotient_len=" << preflight.quotient_len
        << " n_lde=" << preflight.n_lde
        << " row_values="
        << preflight.minimum_total_row_value_bytes
        << " current_batch_lde_bytes="
        << preflight.current_batch_lde_bytes
        << " production_32k_quotient_len="
        << production_preflight.quotient_len
        << " production_32k_lde="
        << production_preflight.n_lde
        << " production_32k_batch_lde_bytes="
        << production_preflight.current_batch_lde_bytes);
}

BOOST_AUTO_TEST_CASE(
    coupled_bank_normalized_v1_terminal_and_registry_fail_closed)
{
    const CoupledBankChild migrated =
        BuildCoupledBankChild();
    const CanonicalBankCtl ctl =
        BuildCanonicalBankCtl(
            migrated.source_pin);
    fp::NormalizedCoupledBankTerminalExecution execution =
        fp::ExecuteNormalizedCoupledBankTerminal(
            migrated.source_pin,
            migrated.row_pin,
            migrated.child.proof,
            migrated.child.seed,
            ctl.manifest,
            ctl.pins,
            ctl.bank_index,
            ctl.schedules[ctl.bank_index],
            ctl.bank_proof);
    BOOST_REQUIRE_MESSAGE(
        execution.valid, execution.note);
    BOOST_CHECK(
        execution.normalized_child_proof_verified);
    BOOST_CHECK(execution.ctl_child_proof_verified);
    BOOST_CHECK(
        execution.public_terminal_composition_verified);
    BOOST_CHECK(!execution.parent_terminal_bound);
    BOOST_CHECK(!execution.legacy_sha_alg_bridge);
    BOOST_CHECK(
        execution.slot.scheme ==
        fp::NormalizedSemanticRootScheme::
            NormalizedAlgHashTerminalV1);
    BOOST_CHECK(
        execution.slot.role ==
        rc::RCStage3RelationRole::CoupledBank);
    BOOST_CHECK_EQUAL(execution.slot.ordinal, 6U);
    BOOST_CHECK_EQUAL(execution.slot.first_endpoint, 27U);
    BOOST_CHECK_EQUAL(execution.slot.endpoint_count, 3U);
    BOOST_CHECK(
        execution.slot.program_table_commitment ==
        rc::constraint_bytecode::CommitProgramTable(
            migrated.table));
    BOOST_CHECK(
        execution.slot.child_trace_row_root ==
        migrated.row_pin.trace_row_commitment);
    BOOST_CHECK(
        execution.slot.child_proof_commitment ==
        fp::ComputeNormalizedAlgAirProofCommitment(
            migrated.child.proof));
    BOOST_CHECK(
        execution.slot.normalized_semantic_root ==
        fp::ComputeNormalizedSemanticRootV1(
            execution.slot));
    BOOST_CHECK(
        execution.slot.slot_commitment ==
        fp::ComputeNormalizedRoleChildSlotCommitment(
            execution.slot));

    fp::FoldBusComposition joined =
        fp::BuildFoldBusComposition(
            migrated.child.cs,
            migrated.child.proof,
            migrated.child.seed);
    BOOST_REQUIRE_MESSAGE(joined.valid, joined.note);
    fp::BytecodeInterpreterAttachment interpreter =
        fp::AttachConstraintBytecodeInterpreter(
            joined, migrated.table);
    BOOST_REQUIRE_MESSAGE(
        interpreter.valid, interpreter.note);
    fp::NormalizedRoleTerminalLayout terminal_layout;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        fp::AttachNormalizedCoupledBankTerminalBinding(
            joined, interpreter,
            migrated.row_pin, execution,
            &terminal_layout, &why),
        why);
    BOOST_CHECK(execution.parent_terminal_bound);
    BOOST_CHECK(
        interpreter.normalized_v1_role_terminal_binding);
    BOOST_CHECK(
        interpreter.normalized_v1_semantic_root ==
        execution.slot.normalized_semantic_root);
    BOOST_CHECK(
        !interpreter.role_semantic_root_terminal_equality);
    BOOST_CHECK_EQUAL(joined.combined.n_columns, 648U);
    BOOST_CHECK_EQUAL(joined.combined.constraints.size(), 622U);
    BOOST_CHECK_EQUAL(joined.violations, 0U);
    const auto alg_hash_audit =
        fp::AssessNormalizedSemanticAlgHashParentClosure(
            joined, interpreter,
            migrated.row_pin, execution);
    BOOST_REQUIRE_EQUAL(
        alg_hash_audit.fields.size(), 7U);
    BOOST_CHECK_EQUAL(
        alg_hash_audit.required_input_lanes, 48U);
    BOOST_CHECK_EQUAL(
        alg_hash_audit.verifier_constant_lanes, 24U);
    BOOST_CHECK_EQUAL(
        alg_hash_audit.proof_authenticated_lanes, 8U);
    BOOST_CHECK_EQUAL(
        alg_hash_audit.missing_proof_bus_lanes, 16U);
    BOOST_CHECK_EQUAL(
        alg_hash_audit.sponge_blocks, 7U);
    BOOST_CHECK_EQUAL(
        alg_hash_audit.additional_permutation_columns,
        910U);
    BOOST_CHECK(
        alg_hash_audit.canonical_alg_hash_available);
    BOOST_CHECK(alg_hash_audit.slot_binding_valid);
    BOOST_CHECK(
        alg_hash_audit.child_trace_root_mapped);
    BOOST_CHECK(
        !alg_hash_audit.
            child_proof_commitment_mapped);
    BOOST_CHECK(
        !alg_hash_audit.
            terminal_bus_commitment_mapped);
    BOOST_CHECK(
        alg_hash_audit.external_root_pin_only);
    BOOST_CHECK(
        !alg_hash_audit.
            in_parent_derivation_complete);
    BOOST_CHECK(
        alg_hash_audit.blocker.find(
            "8_child_proof_commitment_lanes") !=
        std::string::npos);

    const fp::NormalizedRecursiveChildCapabilityAuditV1
        capability =
            fp::AssessNormalizedRecursiveChildCapabilityV1(
                joined, interpreter,
                migrated.row_pin, execution);
    BOOST_REQUIRE_MESSAGE(
        capability.valid, capability.note);
    BOOST_CHECK(
        capability.candidate_role ==
        rc::RCStage3RelationRole::CoupledBank);
    BOOST_CHECK(
        capability.candidate_endpoint ==
        rc::RCStage3RelationEndpoint::
            CoupledBankPages);
    BOOST_CHECK_EQUAL(
        capability.candidate_role_endpoint_count,
        3U);
    BOOST_CHECK_EQUAL(
        capability.candidate_endpoint_count, 1U);
    BOOST_CHECK_EQUAL(
        capability.child_relation_columns, 6U);
    BOOST_CHECK_EQUAL(
        capability.child_relation_constraints, 5U);
    BOOST_CHECK_EQUAL(capability.parent_rows, 8192U);
    BOOST_CHECK_EQUAL(capability.parent_columns, 648U);
    BOOST_CHECK_EQUAL(capability.parent_constraints, 622U);
    BOOST_CHECK(
        capability.native_child_host_verified);
    BOOST_CHECK(capability.authenticated_opening_air);
    BOOST_CHECK(capability.fold_deep_air);
    BOOST_CHECK(capability.relation_bytecode_air);
    BOOST_CHECK(capability.child_trace_root_mapped);
    BOOST_CHECK(
        !capability.child_proof_payload_bound_in_air);
    BOOST_CHECK(
        capability.child_fiat_shamir_replayed_in_air);
    BOOST_CHECK(
        !capability.child_proof_commitment_mapped);
    BOOST_CHECK(
        !capability.ctl_child_verified_in_parent_air);
    BOOST_CHECK(
        !capability.terminal_bus_commitment_mapped);
    BOOST_CHECK(
        !capability.
            normalized_semantic_root_derived_in_parent);
    BOOST_CHECK(
        capability.split_rap_native_verifier_executable);
    BOOST_CHECK(
        !capability.split_rap_multirow_parent_adapter);
    BOOST_CHECK(!capability.endpoint_terminal_equality);
    BOOST_CHECK_EQUAL(
        capability.normalized_root_required_input_lanes,
        48U);
    BOOST_CHECK_EQUAL(
        capability.normalized_root_available_input_lanes,
        32U);
    BOOST_CHECK_EQUAL(
        capability.normalized_root_missing_input_lanes,
        16U);
    BOOST_CHECK_EQUAL(
        capability.
            normalized_root_additional_permutation_columns,
        910U);
    BOOST_REQUIRE_EQUAL(capability.gaps.size(), 7U);
    {
        // Six residuals remain open; FiatShamirReplayAir is present via
        // ledger g4 (AssessChildFsReplayClosureV1().closed).
        uint32_t open_gaps = 0;
        bool fs_gap_present = false;
        for (const auto& gap : capability.gaps) {
            if (!gap.present_in_parent_air) {
                ++open_gaps;
            }
            if (gap.code ==
                fp::NormalizedRecursiveVerifierGapCode::
                    FiatShamirReplayAir) {
                fs_gap_present = gap.present_in_parent_air;
            }
        }
        BOOST_CHECK(fs_gap_present);
        BOOST_CHECK_EQUAL(open_gaps, 6U);
    }
    BOOST_CHECK_EQUAL(
        capability.recursively_consumed_endpoints, 0U);
    BOOST_CHECK_EQUAL(
        capability.recursively_consumed_roles, 0U);
    BOOST_CHECK(
        !capability.recursive_consumption_complete);
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedRecursiveChildCapabilityV1(
            joined, interpreter, migrated.row_pin,
            execution, capability, &why),
        why);

    auto promoted = capability;
    promoted.recursively_consumed_endpoints = 1;
    BOOST_CHECK(
        !fp::ValidateNormalizedRecursiveChildCapabilityV1(
            joined, interpreter, migrated.row_pin,
            execution, promoted, &why));

    auto omitted_gap = capability;
    omitted_gap.gaps.pop_back();
    BOOST_CHECK(
        !fp::ValidateNormalizedRecursiveChildCapabilityV1(
            joined, interpreter, migrated.row_pin,
            execution, omitted_gap, &why));

    auto reordered_gap = capability;
    std::swap(
        reordered_gap.gaps[0],
        reordered_gap.gaps[1]);
    BOOST_CHECK(
        !fp::ValidateNormalizedRecursiveChildCapabilityV1(
            joined, interpreter, migrated.row_pin,
            execution, reordered_gap, &why));

    auto invented_fs = capability;
    invented_fs.child_fiat_shamir_replayed_in_air = false;
    BOOST_CHECK(
        !fp::ValidateNormalizedRecursiveChildCapabilityV1(
            joined, interpreter, migrated.row_pin,
            execution, invented_fs, &why));

    auto substituted_candidate = capability;
    substituted_candidate.candidate_endpoint =
        rc::RCStage3RelationEndpoint::
            EpisodeGemmSignedRange;
    BOOST_CHECK(
        !fp::ValidateNormalizedRecursiveChildCapabilityV1(
            joined, interpreter, migrated.row_pin,
            execution, substituted_candidate, &why));

    static_assert(!fp::kCompleteRecursiveFixedPointExecutable);
    static_assert(!fp::kRecursiveFixedPointConsensusAuthority);

    // Even if an attacker consistently changes the external semantic-root
    // pin, the audit refuses to call that an in-parent derivation because
    // the underlying proof/terminal commitment limbs have no parent source.
    auto changed_proof = execution;
    changed_proof.slot.child_proof_commitment =
        Seed(0xd1);
    changed_proof.slot.normalized_semantic_root =
        fp::ComputeNormalizedSemanticRootV1(
            changed_proof.slot);
    changed_proof.slot.slot_commitment =
        fp::ComputeNormalizedRoleChildSlotCommitment(
            changed_proof.slot);
    auto changed_proof_interpreter = interpreter;
    changed_proof_interpreter.normalized_v1_semantic_root =
        changed_proof.slot.normalized_semantic_root;
    const auto changed_proof_audit =
        fp::AssessNormalizedSemanticAlgHashParentClosure(
            joined, changed_proof_interpreter,
            migrated.row_pin, changed_proof);
    BOOST_CHECK(changed_proof_audit.slot_binding_valid);
    BOOST_CHECK(
        !changed_proof_audit.
            child_proof_commitment_mapped);
    BOOST_CHECK(
        !changed_proof_audit.
            in_parent_derivation_complete);

    auto changed_terminal = execution;
    changed_terminal.slot.terminal_bus_commitment =
        Seed(0xd2);
    changed_terminal.slot.normalized_semantic_root =
        fp::ComputeNormalizedSemanticRootV1(
            changed_terminal.slot);
    changed_terminal.slot.slot_commitment =
        fp::ComputeNormalizedRoleChildSlotCommitment(
            changed_terminal.slot);
    auto changed_terminal_interpreter = interpreter;
    changed_terminal_interpreter.normalized_v1_semantic_root =
        changed_terminal.slot.normalized_semantic_root;
    const auto changed_terminal_audit =
        fp::AssessNormalizedSemanticAlgHashParentClosure(
            joined, changed_terminal_interpreter,
            migrated.row_pin, changed_terminal);
    BOOST_CHECK(
        changed_terminal_audit.slot_binding_valid);
    BOOST_CHECK(
        !changed_terminal_audit.
            terminal_bus_commitment_mapped);
    BOOST_CHECK(
        !changed_terminal_audit.
            in_parent_derivation_complete);

    auto changed_trace = execution;
    changed_trace.slot.child_trace_row_root =
        Seed(0xd3);
    changed_trace.slot.normalized_semantic_root =
        fp::ComputeNormalizedSemanticRootV1(
            changed_trace.slot);
    changed_trace.slot.slot_commitment =
        fp::ComputeNormalizedRoleChildSlotCommitment(
            changed_trace.slot);
    auto changed_trace_interpreter = interpreter;
    changed_trace_interpreter.normalized_v1_semantic_root =
        changed_trace.slot.normalized_semantic_root;
    const auto changed_trace_audit =
        fp::AssessNormalizedSemanticAlgHashParentClosure(
            joined, changed_trace_interpreter,
            migrated.row_pin, changed_trace);
    BOOST_CHECK(
        !changed_trace_audit.slot_binding_valid);
    BOOST_CHECK(
        !changed_trace_audit.child_trace_root_mapped);
    BOOST_CHECK(
        !changed_trace_audit.
            in_parent_derivation_complete);

    std::vector<gf::Fp> semantic_inputs;
    BOOST_REQUIRE_MESSAGE(
        fp::BuildNormalizedSemanticRootInputsV1(
            execution.slot, semantic_inputs, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        semantic_inputs.size(),
        fp::kNormalizedSemanticRootInputLanes);
    BOOST_CHECK_EQUAL(
        gf::Canonical(semantic_inputs[0]),
        fp::kNormalizedSemanticRootDomainLane0);
    BOOST_CHECK_EQUAL(
        gf::Canonical(semantic_inputs[1]),
        fp::kNormalizedSemanticRootDomainLane1);
    BOOST_CHECK_EQUAL(
        gf::Canonical(semantic_inputs[2]),
        fp::kNormalizedSemanticRootV1Version);
    BOOST_CHECK_EQUAL(
        gf::Canonical(semantic_inputs[4]),
        execution.slot.ordinal);
    BOOST_CHECK_EQUAL(
        gf::Canonical(semantic_inputs[6]),
        execution.slot.first_endpoint);
    BOOST_CHECK_EQUAL(
        gf::Canonical(semantic_inputs[7]),
        execution.slot.endpoint_count);
    BOOST_CHECK(
        execution.slot.normalized_semantic_root ==
        rc::Fri3AlgDigestToUint256(
            rc::alg_hash::SpongeHashFp(
                semantic_inputs)));

    const fp::NormalizedSemanticRootSpongeAttachmentV1
        sponge =
            fp::AttachNormalizedSemanticRootSpongeV1(
                joined, execution.slot);
    BOOST_REQUIRE_MESSAGE(sponge.valid, sponge.note);
    BOOST_CHECK_EQUAL(sponge.input_lanes, 48U);
    BOOST_CHECK_EQUAL(sponge.sponge_blocks, 7U);
    BOOST_CHECK_EQUAL(
        sponge.permutation_columns, 910U);
    BOOST_CHECK_EQUAL(
        sponge.input_equality_constraints, 48U);
    BOOST_CHECK_EQUAL(
        sponge.padding_constraints, 8U);
    BOOST_CHECK_EQUAL(
        sponge.capacity_carry_constraints, 28U);
    BOOST_CHECK_EQUAL(
        sponge.output_constraints, 4U);
    BOOST_CHECK_EQUAL(
        sponge.added_constraints, 914U);
    BOOST_CHECK_EQUAL(
        sponge.verifier_constant_lanes, 24U);
    BOOST_CHECK_EQUAL(
        sponge.proof_authenticated_lanes, 8U);
    BOOST_CHECK_EQUAL(
        sponge.externally_pinned_missing_bus_lanes,
        16U);
    BOOST_CHECK(sponge.exact_order);
    BOOST_CHECK(sponge.exact_full_padding_block);
    BOOST_CHECK(sponge.all_inputs_constrained);
    BOOST_CHECK(
        sponge.output_equals_candidate_semantic_root);
    BOOST_CHECK(
        !sponge.all_inputs_recursively_proof_owned);
    BOOST_CHECK_EQUAL(sponge.violations, 0U);
    BOOST_CHECK_EQUAL(joined.combined.n_columns, 1606U);
    BOOST_CHECK_EQUAL(
        joined.combined.constraints.size(), 1536U);
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedSemanticRootSpongeV1(
            joined, execution.slot, sponge, &why),
        why);

    // Canonical order and all sixteen formerly missing lanes are now
    // constrained as local public pins. They still do not become recursive
    // proof outputs merely by being present in the sponge.
    const uint32_t proof_commitment_lane =
        sponge.layout.Input(32);
    const gf::Fp3 saved_missing_lane =
        joined.columns[
            proof_commitment_lane][0];
    joined.columns[
        proof_commitment_lane][0] =
        gf::Add(
            saved_missing_lane,
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedSemanticRootSpongeV1(
            joined, execution.slot, sponge, &why));
    joined.columns[
        proof_commitment_lane][0] =
        saved_missing_lane;

    uint32_t first_distinct = 0;
    uint32_t second_distinct = 1;
    while (second_distinct <
               semantic_inputs.size() &&
           semantic_inputs[first_distinct] ==
               semantic_inputs[second_distinct]) {
        ++second_distinct;
    }
    BOOST_REQUIRE_LT(
        second_distinct, semantic_inputs.size());
    std::swap(
        joined.columns[
            sponge.layout.Input(first_distinct)][0],
        joined.columns[
            sponge.layout.Input(second_distinct)][0]);
    BOOST_CHECK(
        !fp::ValidateNormalizedSemanticRootSpongeV1(
            joined, execution.slot, sponge, &why));
    std::swap(
        joined.columns[
            sponge.layout.Input(first_distinct)][0],
        joined.columns[
            sponge.layout.Input(second_distinct)][0]);

    const ar::PermLayout padding_permutation =
        sponge.layout.Permutation(6);
    const gf::Fp3 saved_padding =
        joined.columns[
            padding_permutation.InputCol(0)][0];
    joined.columns[
        padding_permutation.InputCol(0)][0] =
        gf::Add(
            saved_padding, gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedSemanticRootSpongeV1(
            joined, execution.slot, sponge, &why));
    joined.columns[
        padding_permutation.InputCol(0)][0] =
        saved_padding;

    auto promoted_sponge = sponge;
    promoted_sponge.all_inputs_recursively_proof_owned =
        true;
    BOOST_CHECK(
        !fp::ValidateNormalizedSemanticRootSpongeV1(
            joined, execution.slot,
            promoted_sponge, &why));

    auto removed_constraint =
        std::move(
            joined.combined.constraints.back());
    joined.combined.constraints.pop_back();
    BOOST_CHECK(
        !fp::ValidateNormalizedSemanticRootSpongeV1(
            joined, execution.slot, sponge, &why));
    joined.combined.constraints.push_back(
        std::move(removed_constraint));

    const auto tuple_adapter =
        fp::BuildNormalizedCoupledBankCtlTupleExportAdapterV1(
            migrated.source_pin,
            migrated.row_pin,
            migrated.child.proof,
            migrated.child.seed);
    BOOST_REQUIRE_MESSAGE(
        tuple_adapter.valid,
        tuple_adapter.note);
    BOOST_CHECK(
        tuple_adapter.canonical_tuple_manifest);
    BOOST_CHECK(
        tuple_adapter.producer_relation_proof_verified);
    BOOST_CHECK(
        tuple_adapter.producer_output_column_identified);
    BOOST_CHECK(
        !tuple_adapter.producer_cells_exported);
    BOOST_CHECK(
        !tuple_adapter.consumer_proof_bound);
    BOOST_CHECK(
        !tuple_adapter.consumer_cells_exported);
    BOOST_CHECK(
        !tuple_adapter.shared_post_commit_challenges);
    BOOST_CHECK(
        !tuple_adapter.cross_proof_logup_identity);
    BOOST_CHECK(!tuple_adapter.executable);
    BOOST_CHECK(!tuple_adapter.semantic_closure);
    BOOST_CHECK_EQUAL(
        tuple_adapter.required_event_count,
        uint64_t{2} *
            migrated.source_pin.logical_rows);
    BOOST_CHECK_EQUAL(
        tuple_adapter.required_send_count,
        migrated.source_pin.logical_rows);
    BOOST_CHECK_EQUAL(
        tuple_adapter.required_receive_count,
        migrated.source_pin.logical_rows);
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedCoupledBankCtlTupleExportAdapterV1(
            migrated.source_pin,
            migrated.row_pin,
            migrated.child.proof,
            migrated.child.seed,
            tuple_adapter,
            &why),
        why);

    auto false_tuple_closure = tuple_adapter;
    false_tuple_closure.producer_cells_exported = true;
    false_tuple_closure.consumer_proof_bound = true;
    false_tuple_closure.consumer_cells_exported = true;
    false_tuple_closure.shared_post_commit_challenges = true;
    false_tuple_closure.cross_proof_logup_identity = true;
    false_tuple_closure.executable = true;
    false_tuple_closure.semantic_closure = true;
    BOOST_CHECK(
        !fp::ValidateNormalizedCoupledBankCtlTupleExportAdapterV1(
            migrated.source_pin,
            migrated.row_pin,
            migrated.child.proof,
            migrated.child.seed,
            false_tuple_closure,
            &why));

    auto bad_tuple_manifest = tuple_adapter;
    ++bad_tuple_manifest.producer_source_column;
    BOOST_CHECK(
        !fp::ValidateNormalizedCoupledBankCtlTupleExportAdapterV1(
            migrated.source_pin,
            migrated.row_pin,
            migrated.child.proof,
            migrated.child.seed,
            bad_tuple_manifest,
            &why));

    const fp::NormalizedDeep64CtlTerminalAttachmentV1
        ctl_terminal =
            fp::BuildNormalizedDeep64CtlTerminalV1(
                joined, migrated.source_pin,
                execution.slot,
                sponge, ctl.manifest, ctl.pins,
                ctl.bank_index,
                ctl.schedules[ctl.bank_index],
                ctl.bank_proof);
    BOOST_REQUIRE_MESSAGE(
        ctl_terminal.valid, ctl_terminal.note);
    // BuildNormalizedCoupledBankCtlRootScheduleV1 currently emits one
    // send/receive pair per digest limb (2*8), not per dequant column.
    BOOST_CHECK_EQUAL(ctl_terminal.event_count, 16U);
    BOOST_CHECK_EQUAL(
        ctl_terminal.send_count,
        ctl_terminal.receive_count);
    BOOST_CHECK(
        ctl_terminal.canonical_relation_root_tuples);
    BOOST_CHECK(
        ctl_terminal.relation_value_column_bound);
    BOOST_CHECK(
        ctl_terminal.prechallenge_commitments_bound);
    BOOST_CHECK(
        ctl_terminal.challenges_after_commitments);
    BOOST_CHECK(
        ctl_terminal.
            denominator_nonzero_constraints_verified);
    BOOST_CHECK(
        ctl_terminal.
            multiplicity_accumulators_verified);
    BOOST_CHECK(
        ctl_terminal.selected_child_terminal_zero);
    BOOST_CHECK(
        ctl_terminal.
            public_pin_terminal_equality_verified);
    BOOST_CHECK(
        !ctl_terminal.
            all_participant_child_proofs_verified);
    BOOST_CHECK(
        !ctl_terminal.
            global_terminal_equality_verified);
    BOOST_CHECK(ctl_terminal.proof_codec_canonical);
    BOOST_CHECK(
        ctl_terminal.proof_field_transport_bound);
    BOOST_CHECK(
        ctl_terminal.
            terminal_semantic_lanes_linked);
    BOOST_CHECK(
        ctl_terminal.
            semantic_slot_and_sponge_binding_verified);
    BOOST_CHECK(
        ctl_terminal.child_proof_verified_natively);
    BOOST_CHECK(
        ctl_terminal.root_inventory_transport_only);
    BOOST_CHECK(
        !ctl_terminal.
            actual_producer_relation_tuples_bound);
    BOOST_CHECK(
        !ctl_terminal.
            actual_consumer_proof_tuples_bound);
    BOOST_CHECK(
        !ctl_terminal.
            cross_proof_logup_identity_verified);
    BOOST_CHECK(!ctl_terminal.ctl_semantic_closure);
    BOOST_CHECK(
        !ctl_terminal.
            complete_sha_fiat_shamir_replay_in_parent);
    BOOST_CHECK(!ctl_terminal.endpoint_promoted);
    BOOST_CHECK(!ctl_terminal.authority);
    BOOST_CHECK_EQUAL(
        ctl_terminal.recursive_endpoints_consumed,
        0U);
    BOOST_CHECK_EQUAL(
        ctl_terminal.recursive_roles_consumed,
        0U);
    BOOST_CHECK(!ctl_terminal.recursively_consumed);
    BOOST_CHECK_GT(
        ctl_terminal.proof_codec_bytes, 0U);
    BOOST_CHECK_GT(
        ctl_terminal.proof_field_count, 0U);
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedDeep64CtlTerminalV1(
            joined, migrated.source_pin,
            execution.slot,
            sponge, ctl.manifest, ctl.pins,
            ctl.bank_index,
            ctl.schedules[ctl.bank_index],
            ctl.bank_proof, ctl_terminal,
            &why),
        why);

    // Packed CTL-in-parent attach: codec limbs use a fixed-rate row bus
    // (not one parent-height column per limb — that path OOM'd ~62GiB).
    {
        fp::FoldBusComposition ctl_air_joined = joined;
        const auto ctl_parent_air =
            fp::AttachNormalizedDeep64CtlChildVerifierInParentAirV1(
                ctl_air_joined, migrated.source_pin, ctl_terminal,
                ctl.manifest, ctl.pins, ctl.bank_index,
                ctl.schedules[ctl.bank_index],
                ctl.bank_proof);
        BOOST_REQUIRE_MESSAGE(
            ctl_parent_air.valid, ctl_parent_air.note);
        BOOST_CHECK_EQUAL(
            ctl_parent_air.layout.proof_field_lanes,
            fp::kNormalizedAlgAirProofFieldBusRate);
        BOOST_CHECK_EQUAL(
            ctl_parent_air.layout.End(),
            ctl_parent_air.layout.ctl_column_base +
                rc::stage3_ctl_col::NUM_COLUMNS +
                ctl_parent_air.layout.proof_field_lanes + 1);
        BOOST_CHECK_LT(
            ctl_parent_air.added_columns,
            ctl_terminal.proof_field_count);
        BOOST_CHECK(ctl_parent_air.ctl_equations_hosted);
        BOOST_CHECK(ctl_parent_air.proof_fields_equality_wired);
        BOOST_CHECK(ctl_parent_air.forgery_rejected);
        BOOST_CHECK_EQUAL(ctl_parent_air.violations, 0U);
        BOOST_CHECK_MESSAGE(
            fp::ValidateNormalizedDeep64CtlChildVerifierInParentAirV1(
                ctl_air_joined, migrated.source_pin, ctl_terminal,
                ctl.manifest, ctl.pins, ctl.bank_index,
                ctl.schedules[ctl.bank_index],
                ctl.bank_proof, ctl_parent_air, &why),
            why);
    }

    auto cloned_ctl_schedule =
        ctl.schedules[ctl.bank_index];
    cloned_ctl_schedule.events.push_back(
        cloned_ctl_schedule.events.front());
    BOOST_CHECK(
        !fp::BuildNormalizedDeep64CtlTerminalV1(
             joined, migrated.source_pin,
             execution.slot,
             sponge, ctl.manifest, ctl.pins,
             ctl.bank_index,
             cloned_ctl_schedule,
             ctl.bank_proof)
             .valid);

    auto bad_ctl_counts = ctl.pins;
    ++bad_ctl_counts[ctl.bank_index].event_count;
    BOOST_CHECK(
        !fp::BuildNormalizedDeep64CtlTerminalV1(
             joined, migrated.source_pin,
             execution.slot,
             sponge, ctl.manifest,
             bad_ctl_counts, ctl.bank_index,
             ctl.schedules[ctl.bank_index],
             ctl.bank_proof)
             .valid);

    auto bad_ctl_multiplicity =
        ctl.schedules[ctl.bank_index];
    BOOST_REQUIRE_GT(
        bad_ctl_multiplicity.events.size(), 1U);
    bad_ctl_multiplicity.events[1].multiplicity = 1;
    BOOST_CHECK(
        !fp::BuildNormalizedDeep64CtlTerminalV1(
             joined, migrated.source_pin,
             execution.slot,
             sponge, ctl.manifest, ctl.pins,
             ctl.bank_index,
             bad_ctl_multiplicity,
             ctl.bank_proof)
             .valid);

    auto bad_ctl_order =
        ctl.schedules[ctl.bank_index];
    std::swap(
        bad_ctl_order.events[0],
        bad_ctl_order.events[2]);
    BOOST_CHECK(
        !fp::BuildNormalizedDeep64CtlTerminalV1(
             joined, migrated.source_pin,
             execution.slot,
             sponge, ctl.manifest, ctl.pins,
             ctl.bank_index,
             bad_ctl_order,
             ctl.bank_proof)
             .valid);

    auto bad_ctl_transport = ctl_terminal;
    BOOST_REQUIRE(
        !bad_ctl_transport.proof_fields.empty());
    bad_ctl_transport.proof_fields[0] =
        gf::Add(
            bad_ctl_transport.proof_fields[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedDeep64CtlTerminalV1(
            joined, migrated.source_pin,
            execution.slot,
            sponge, ctl.manifest, ctl.pins,
            ctl.bank_index,
            ctl.schedules[ctl.bank_index],
            ctl.bank_proof, bad_ctl_transport,
            &why));

    auto noncanonical_ctl_transport = ctl_terminal;
    BOOST_REQUIRE(
        !noncanonical_ctl_transport.proof_fields.empty());
    BOOST_REQUIRE_LE(
        noncanonical_ctl_transport.proof_fields[0].c0,
        std::numeric_limits<uint64_t>::max() -
            gf::kP);
    noncanonical_ctl_transport.proof_fields[0].c0 +=
        gf::kP;
    BOOST_CHECK(
        !fp::ValidateNormalizedDeep64CtlTerminalV1(
            joined, migrated.source_pin,
            execution.slot,
            sponge, ctl.manifest, ctl.pins,
            ctl.bank_index,
            ctl.schedules[ctl.bank_index],
            ctl.bank_proof,
            noncanonical_ctl_transport,
            &why));

    auto bad_ctl_export = ctl_terminal;
    bad_ctl_export.relation_export.
        prechallenge_column_roots[
            rc::stage3_ctl_col::VALUE] =
        Seed(0xee);
    BOOST_CHECK(
        !fp::ValidateNormalizedDeep64CtlTerminalV1(
            joined, migrated.source_pin,
            execution.slot,
            sponge, ctl.manifest, ctl.pins,
            ctl.bank_index,
            ctl.schedules[ctl.bank_index],
            ctl.bank_proof, bad_ctl_export,
            &why));

    auto erased_ctl_residual = ctl_terminal;
    BOOST_REQUIRE(
        !erased_ctl_residual.residuals.empty());
    erased_ctl_residual.residuals.erase(
        erased_ctl_residual.residuals.begin());
    BOOST_CHECK(
        !fp::ValidateNormalizedDeep64CtlTerminalV1(
            joined, migrated.source_pin,
            execution.slot,
            sponge, ctl.manifest, ctl.pins,
            ctl.bank_index,
            ctl.schedules[ctl.bank_index],
            ctl.bank_proof, erased_ctl_residual,
            &why));

    auto stale_ctl_slot = execution.slot;
    stale_ctl_slot.statement_commitment =
        Seed(0xef);
    stale_ctl_slot.normalized_semantic_root =
        fp::ComputeNormalizedSemanticRootV1(
            stale_ctl_slot);
    stale_ctl_slot.slot_commitment =
        fp::ComputeNormalizedRoleChildSlotCommitment(
            stale_ctl_slot);
    BOOST_CHECK(
        !fp::BuildNormalizedDeep64CtlTerminalV1(
             joined, migrated.source_pin,
             stale_ctl_slot,
             sponge, ctl.manifest, ctl.pins,
             ctl.bank_index,
             ctl.schedules[ctl.bank_index],
             ctl.bank_proof)
             .valid);

    auto false_ctl_authority = ctl_terminal;
    false_ctl_authority.
        complete_sha_fiat_shamir_replay_in_parent =
            true;
    false_ctl_authority.endpoint_promoted = true;
    false_ctl_authority.authority = true;
    false_ctl_authority.
        recursive_endpoints_consumed = 1;
    false_ctl_authority.
        recursive_roles_consumed = 1;
    false_ctl_authority.recursively_consumed = true;
    BOOST_CHECK(
        !fp::ValidateNormalizedDeep64CtlTerminalV1(
            joined, migrated.source_pin,
            execution.slot,
            sponge, ctl.manifest, ctl.pins,
            ctl.bank_index,
            ctl.schedules[ctl.bank_index],
            ctl.bank_proof, false_ctl_authority,
            &why));

    std::vector<gf::Fp> proof_fields;
    uint32_t proof_codec_bytes = 0;
    uint32_t proof_codec_words = 0;
    uint32_t proof_supplemental_fields = 0;
    BOOST_REQUIRE_MESSAGE(
        fp::BuildNormalizedAlgAirProofFieldTranscriptV1(
            migrated.child.proof, proof_fields,
            &proof_codec_bytes,
            &proof_codec_words,
            &proof_supplemental_fields,
            &why),
        why);
    BOOST_CHECK(!proof_fields.empty());
    BOOST_CHECK_GT(proof_codec_bytes, 0U);
    BOOST_CHECK_EQUAL(
        proof_codec_words,
        (proof_codec_bytes + 3) / 4);
    BOOST_CHECK_GT(proof_supplemental_fields, 0U);
    BOOST_CHECK(
        execution.slot.child_proof_commitment ==
        rc::Fri3AlgDigestToUint256(
            rc::alg_hash::SpongeHashFp(
                proof_fields)));

    const fp::NormalizedAlgAirProofFieldBusAttachmentV1
        proof_bus =
            fp::AttachNormalizedAlgAirProofFieldBusV1(
                joined, migrated.child.proof,
                execution.slot, sponge);
    BOOST_REQUIRE_MESSAGE(
        proof_bus.valid, proof_bus.note);
    BOOST_CHECK_EQUAL(
        proof_bus.transcript_fields,
        proof_fields.size());
    BOOST_CHECK_EQUAL(
        proof_bus.batch_codec_bytes,
        proof_codec_bytes);
    BOOST_CHECK_EQUAL(
        proof_bus.batch_codec_words,
        proof_codec_words);
    BOOST_CHECK_EQUAL(
        proof_bus.supplemental_fields,
        proof_supplemental_fields);
    BOOST_CHECK_LE(
        proof_bus.active_sponge_rows,
        joined.combined.n_rows);
    BOOST_CHECK_EQUAL(proof_bus.added_columns, 140U);
    BOOST_CHECK_EQUAL(
        proof_bus.added_constraints, 153U);
    BOOST_CHECK(proof_bus.exact_codec_bytes_bound);
    BOOST_CHECK(
        proof_bus.all_supplemental_fields_bound);
    BOOST_CHECK(
        proof_bus.
            row_fold_ood_deep_query_path_fields_present);
    BOOST_CHECK(
        proof_bus.proof_commitment_derived_in_parent);
    BOOST_CHECK(
        proof_bus.
            proof_commitment_semantic_lanes_linked);
    BOOST_CHECK(
        !proof_bus.
            proof_fields_sourced_from_verifier_chips);
    BOOST_CHECK(
        !proof_bus.
            complete_fiat_shamir_replay_in_parent);
    BOOST_CHECK(
        !proof_bus.
            ctl_commitment_sourced_from_child_verifier);
    BOOST_CHECK(!proof_bus.recursively_consumed);
    BOOST_REQUIRE_EQUAL(proof_bus.residuals.size(), 4U);
    BOOST_CHECK_EQUAL(proof_bus.violations, 0U);
    BOOST_CHECK_EQUAL(joined.combined.n_columns, 1746U);
    BOOST_CHECK_EQUAL(
        joined.combined.constraints.size(), 1689U);
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedAlgAirProofFieldBusV1(
            joined, migrated.child.proof,
            execution.slot, sponge,
            proof_bus, &why),
        why);

    // CompleteFP residual chip: ProofFieldBus closes ChildProofCommitmentBus
    // (8 lanes). TerminalBusCommitmentBus then closes terminal lanes + semantic
    // root. Payload/CTL-child-verifier/endpoint/SplitRap/CompleteFP remain open.
    const auto alg_hash_with_bus =
        fp::PromoteNormalizedSemanticProofCommitmentFromFieldBusV1(
            fp::AssessNormalizedSemanticAlgHashParentClosure(
                joined, interpreter, migrated.row_pin,
                execution),
            proof_bus, execution.slot);
    BOOST_CHECK(alg_hash_with_bus.child_proof_commitment_mapped);
    BOOST_CHECK_EQUAL(
        alg_hash_with_bus.proof_authenticated_lanes, 16U);
    BOOST_CHECK_EQUAL(
        alg_hash_with_bus.missing_proof_bus_lanes, 8U);
    BOOST_CHECK(
        !alg_hash_with_bus.terminal_bus_commitment_mapped);
    BOOST_CHECK(
        !alg_hash_with_bus.in_parent_derivation_complete);
    BOOST_CHECK(
        alg_hash_with_bus.blocker.find(
            "proof_commitment_bus_closed_via_proof_field_bus") !=
        std::string::npos);

    // Attach on a composition copy so later codec/remote chips still see
    // ProofFieldBus as the tip of `joined`.
    fp::FoldBusComposition terminal_joined = joined;
    const fp::NormalizedTerminalBusCommitmentBusAttachmentV1
        terminal_bus =
            fp::AttachNormalizedTerminalBusCommitmentBusV1(
                terminal_joined, ctl.manifest, ctl.pins,
                ctl.bank_index,
                ctl.schedules[ctl.bank_index], execution.slot,
                sponge);
    BOOST_REQUIRE_MESSAGE(terminal_bus.valid, terminal_bus.note);
    BOOST_CHECK(
        terminal_bus.terminal_bus_commitment_derived_in_parent);
    BOOST_CHECK(terminal_bus.terminal_bus_semantic_lanes_linked);
    BOOST_CHECK(!terminal_bus.ctl_child_verified_in_parent_air);
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedTerminalBusCommitmentBusV1(
            terminal_joined, ctl.manifest, ctl.pins, ctl.bank_index,
            ctl.schedules[ctl.bank_index], execution.slot,
            sponge, terminal_bus, &why),
        why);

    const auto alg_hash_with_terminal =
        fp::PromoteNormalizedSemanticTerminalBusFromCommitmentBusV1(
            alg_hash_with_bus, terminal_bus, execution.slot);
    BOOST_CHECK(alg_hash_with_terminal.terminal_bus_commitment_mapped);
    BOOST_CHECK_EQUAL(
        alg_hash_with_terminal.proof_authenticated_lanes, 24U);
    BOOST_CHECK_EQUAL(
        alg_hash_with_terminal.missing_proof_bus_lanes, 0U);
    BOOST_CHECK(
        alg_hash_with_terminal.in_parent_derivation_complete);

    const fp::NormalizedRecursiveChildCapabilityAuditV1
        capability_with_bus =
            fp::AssessNormalizedRecursiveChildCapabilityWithProofBusV1(
                terminal_joined, interpreter, migrated.row_pin,
                execution, proof_bus, &terminal_bus);
    BOOST_REQUIRE_MESSAGE(
        capability_with_bus.valid, capability_with_bus.note);
    BOOST_CHECK(
        capability_with_bus.child_proof_commitment_mapped);
    BOOST_CHECK(
        capability_with_bus.terminal_bus_commitment_mapped);
    BOOST_CHECK(
        capability_with_bus.normalized_semantic_root_derived_in_parent);
    BOOST_CHECK_EQUAL(
        capability_with_bus.normalized_root_available_input_lanes,
        48U);
    BOOST_CHECK_EQUAL(
        capability_with_bus.normalized_root_missing_input_lanes,
        0U);
    BOOST_CHECK(
        !capability_with_bus.child_proof_payload_bound_in_air);
    BOOST_CHECK(
        !capability_with_bus.ctl_child_verified_in_parent_air);
    BOOST_CHECK(
        !capability_with_bus.endpoint_terminal_equality);
    {
        uint32_t open_gaps = 0;
        bool commit_gap_present = false;
        bool semantic_gap_present = false;
        bool ctl_gap_present = false;
        for (const auto& gap : capability_with_bus.gaps) {
            if (!gap.present_in_parent_air) {
                ++open_gaps;
            }
            if (gap.code ==
                fp::NormalizedRecursiveVerifierGapCode::
                    ChildProofCommitmentBus) {
                commit_gap_present = gap.present_in_parent_air;
                BOOST_CHECK_EQUAL(gap.mapped_lanes, 8U);
            }
            if (gap.code ==
                fp::NormalizedRecursiveVerifierGapCode::
                    NormalizedSemanticRootAlgHash) {
                semantic_gap_present = gap.present_in_parent_air;
            }
            if (gap.code ==
                fp::NormalizedRecursiveVerifierGapCode::
                    CtlChildVerifierAndTerminalBus) {
                ctl_gap_present = gap.present_in_parent_air;
            }
        }
        BOOST_CHECK(commit_gap_present);
        BOOST_CHECK(semantic_gap_present);
        BOOST_CHECK(!ctl_gap_present);
        BOOST_CHECK_EQUAL(open_gaps, 4U);
    }
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedRecursiveChildCapabilityWithProofBusV1(
            terminal_joined, interpreter, migrated.row_pin, execution,
            proof_bus, capability_with_bus, &why, &terminal_bus),
        why);
    BOOST_CHECK(
        capability_with_bus.note.find(
            "terminal_bus_closed_via_commitment_bus") !=
        std::string::npos);
    BOOST_TEST_MESSAGE(capability_with_bus.note);
    static_assert(!fp::kCompleteRecursiveFixedPointExecutable);

    const gf::Fp3 saved_proof_field =
        joined.columns[
            proof_bus.layout.Field(0)][0];
    joined.columns[
        proof_bus.layout.Field(0)][0] =
        gf::Add(
            saved_proof_field,
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirProofFieldBusV1(
            joined, migrated.child.proof,
            execution.slot, sponge,
            proof_bus, &why));
    joined.columns[
        proof_bus.layout.Field(0)][0] =
        saved_proof_field;

    const uint32_t proof_padding_lane =
        proof_fields.size() %
            fp::kNormalizedAlgAirProofFieldBusRate;
    const uint32_t proof_padding_row =
        proof_bus.active_sponge_rows - 1;
    const gf::Fp3 saved_proof_padding =
        joined.columns[
            proof_bus.layout.Field(
                proof_padding_lane)]
            [proof_padding_row];
    joined.columns[
        proof_bus.layout.Field(
            proof_padding_lane)]
        [proof_padding_row] =
        gf::Add(
            saved_proof_padding,
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirProofFieldBusV1(
            joined, migrated.child.proof,
            execution.slot, sponge,
            proof_bus, &why));
    joined.columns[
        proof_bus.layout.Field(
            proof_padding_lane)]
        [proof_padding_row] =
        saved_proof_padding;

    auto substituted_proof =
        migrated.child.proof;
    BOOST_REQUIRE(
        !substituted_proof.batch.queries.empty());
    BOOST_REQUIRE(
        !substituted_proof.batch.queries[0]
             .row.values.empty());
    substituted_proof.batch.queries[0]
        .row.values[0] =
        gf::Add(
            substituted_proof.batch.queries[0]
                .row.values[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirProofFieldBusV1(
            joined, substituted_proof,
            execution.slot, sponge,
            proof_bus, &why));

    auto promoted_proof_bus = proof_bus;
    promoted_proof_bus.
        proof_fields_sourced_from_verifier_chips =
            true;
    promoted_proof_bus.recursively_consumed = true;
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirProofFieldBusV1(
            joined, migrated.child.proof,
            execution.slot, sponge,
            promoted_proof_bus, &why));

    auto removed_bus_constraint =
        std::move(
            joined.combined.constraints.back());
    joined.combined.constraints.pop_back();
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirProofFieldBusV1(
            joined, migrated.child.proof,
            execution.slot, sponge,
            proof_bus, &why));
    joined.combined.constraints.push_back(
        std::move(removed_bus_constraint));

    fp::NormalizedAlgAirBatchCodecMapV1 codec_map;
    BOOST_REQUIRE_MESSAGE(
        fp::BuildNormalizedAlgAirBatchCodecMapV1(
            migrated.child.proof.batch,
            codec_map, &why),
        why);
    BOOST_CHECK(codec_map.valid);
    BOOST_CHECK_EQUAL(
        codec_map.codec_bytes,
        proof_codec_bytes);
    BOOST_CHECK_EQUAL(
        codec_map.codec_words,
        proof_codec_words);
    BOOST_CHECK_EQUAL(
        codec_map.entries.size(),
        codec_map.codec_words);
    BOOST_CHECK_GT(codec_map.fp_elements, 0U);
    BOOST_CHECK(codec_map.exact_dense_coverage);
    BOOST_CHECK(codec_map.exact_little_endian);
    BOOST_CHECK(codec_map.canonical_roundtrip);
    BOOST_CHECK(codec_map.no_trailing_bytes);
    for (uint32_t word = 0;
         word < codec_map.entries.size();
         ++word) {
        BOOST_CHECK_EQUAL(
            codec_map.entries[word].word_index,
            word);
        BOOST_CHECK_EQUAL(
            codec_map.entries[word].byte_offset,
            4 * word);
    }

    std::vector<unsigned char> canonical_codec;
    const size_t encoded_codec =
        rc::SerializeFri3AlgBatchProof(
            migrated.child.proof.batch,
            canonical_codec);
    BOOST_REQUIRE_EQUAL(
        encoded_codec, canonical_codec.size());
    BOOST_REQUIRE_GT(encoded_codec, 0U);
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedAlgAirBatchCodecBytesV1(
            migrated.child.proof.batch,
            canonical_codec, &why),
        why);
    auto mutated_codec = canonical_codec;
    BOOST_REQUIRE_GT(mutated_codec.size(), 8U);
    mutated_codec[8] ^= 1;
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirBatchCodecBytesV1(
            migrated.child.proof.batch,
            mutated_codec, &why));
    auto trailing_codec = canonical_codec;
    trailing_codec.push_back(0);
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirBatchCodecBytesV1(
            migrated.child.proof.batch,
            trailing_codec, &why));
    auto reordered_codec = canonical_codec;
    std::swap(
        reordered_codec[0],
        reordered_codec[4]);
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirBatchCodecBytesV1(
            migrated.child.proof.batch,
            reordered_codec, &why));

    const fp::NormalizedAlgAirCodecDecoderAttachmentV1
        codec_decoder =
            fp::AttachNormalizedAlgAirCodecDecoderV1(
                joined, migrated.child.proof,
                proof_bus);
    BOOST_REQUIRE_MESSAGE(
        codec_decoder.valid,
        codec_decoder.note);
    BOOST_CHECK_EQUAL(
        codec_decoder.active_word_slots,
        proof_codec_words);
    BOOST_CHECK_EQUAL(
        codec_decoder.valid_byte_slots,
        proof_codec_bytes);
    BOOST_CHECK_EQUAL(
        codec_decoder.canonical_fp_elements,
        codec_map.fp_elements);
    BOOST_CHECK_EQUAL(
        codec_decoder.added_columns, 352U);
    BOOST_CHECK_EQUAL(
        codec_decoder.added_constraints, 362U);
    BOOST_CHECK(
        codec_decoder.exact_length_constrained);
    BOOST_CHECK(codec_decoder.every_word_decomposed);
    BOOST_CHECK(
        codec_decoder.every_byte_range_checked);
    BOOST_CHECK(
        codec_decoder.
            little_endian_recomposition_constrained);
    BOOST_CHECK(
        codec_decoder.final_word_padding_zero);
    BOOST_CHECK(
        codec_decoder.every_fp_encoding_canonical);
    BOOST_CHECK(
        codec_decoder.no_unconsumed_codec_bytes);
    BOOST_CHECK(
        !codec_decoder.
            every_chip_consumer_equality_mapped);
    BOOST_CHECK(
        !codec_decoder.
            complete_fiat_shamir_replay_in_parent);
    BOOST_CHECK(!codec_decoder.recursively_consumed);
    BOOST_REQUIRE_EQUAL(
        codec_decoder.residuals.size(), 3U);
    BOOST_CHECK_EQUAL(
        joined.combined.n_columns, 2098U);
    BOOST_CHECK_EQUAL(
        joined.combined.constraints.size(), 2051U);
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedAlgAirCodecDecoderV1(
            joined, migrated.child.proof,
            proof_bus, codec_decoder, &why),
        why);

    constexpr uint32_t FIRST_CODEC_POSITION = 5;
    const uint32_t first_codec_row =
        FIRST_CODEC_POSITION /
            fp::kNormalizedAlgAirCodecWordLanes;
    const uint32_t first_codec_lane =
        FIRST_CODEC_POSITION %
            fp::kNormalizedAlgAirCodecWordLanes;
    const gf::Fp3 saved_codec_byte =
        joined.columns[
            codec_decoder.layout.Byte(
                first_codec_lane, 0)]
            [first_codec_row];
    joined.columns[
        codec_decoder.layout.Byte(
            first_codec_lane, 0)]
        [first_codec_row] =
        gf::Add(
            saved_codec_byte,
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirCodecDecoderV1(
            joined, migrated.child.proof,
            proof_bus, codec_decoder, &why));
    joined.columns[
        codec_decoder.layout.Byte(
            first_codec_lane, 0)]
        [first_codec_row] =
            saved_codec_byte;

    const gf::Fp3 saved_codec_bit =
        joined.columns[
            codec_decoder.layout.Bit(
                first_codec_lane, 0, 0)]
            [first_codec_row];
    joined.columns[
        codec_decoder.layout.Bit(
            first_codec_lane, 0, 0)]
        [first_codec_row] =
        gf::Add(
            saved_codec_bit,
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirCodecDecoderV1(
            joined, migrated.child.proof,
            proof_bus, codec_decoder, &why));
    joined.columns[
        codec_decoder.layout.Bit(
            first_codec_lane, 0, 0)]
        [first_codec_row] =
            saved_codec_bit;

    auto promoted_codec_decoder = codec_decoder;
    promoted_codec_decoder.
        every_chip_consumer_equality_mapped = true;
    promoted_codec_decoder.recursively_consumed = true;
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirCodecDecoderV1(
            joined, migrated.child.proof,
            proof_bus, promoted_codec_decoder,
            &why));

    auto removed_decoder_constraint =
        std::move(
            joined.combined.constraints.back());
    joined.combined.constraints.pop_back();
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirCodecDecoderV1(
            joined, migrated.child.proof,
            proof_bus, codec_decoder, &why));
    joined.combined.constraints.push_back(
        std::move(removed_decoder_constraint));

    const fp::NormalizedAlgAirCodecCtlAttachmentV1
        codec_ctl =
            fp::AttachNormalizedAlgAirCodecCtlV1(
                joined, proof_bus, codec_decoder);
    BOOST_REQUIRE_MESSAGE(
        codec_ctl.valid, codec_ctl.note);
    BOOST_CHECK_GT(codec_ctl.semantic_events, 0U);
    BOOST_CHECK_EQUAL(
        codec_ctl.producer_events,
        codec_ctl.semantic_events);
    BOOST_CHECK_EQUAL(
        codec_ctl.consumer_events,
        codec_ctl.semantic_events);
    BOOST_CHECK_EQUAL(codec_ctl.added_columns, 90U);
    BOOST_CHECK_EQUAL(
        codec_ctl.added_constraints, 62U);
    BOOST_CHECK(codec_ctl.exact_semantic_addresses);
    BOOST_CHECK(codec_ctl.exact_multiplicity_one);
    BOOST_CHECK(
        codec_ctl.
            dual_rational_identity_terminal_zero);
    BOOST_CHECK(codec_ctl.denominator_nonzero);
    BOOST_CHECK(codec_ctl.decoder_values_aliased);
    BOOST_CHECK(
        !codec_ctl.
            consumer_values_sourced_from_remote_chips);
    BOOST_CHECK(
        !codec_ctl.
            complete_fiat_shamir_replay_in_parent);
    BOOST_CHECK(!codec_ctl.recursively_consumed);
    BOOST_REQUIRE_EQUAL(codec_ctl.residuals.size(), 3U);
    BOOST_CHECK_EQUAL(
        joined.combined.n_columns, 2188U);
    BOOST_CHECK_EQUAL(
        joined.combined.constraints.size(), 2113U);
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedAlgAirCodecCtlV1(
            joined, proof_bus, codec_decoder,
            codec_ctl, &why),
        why);

    // Missing one consumer destroys exact multiplicity.
    const uint32_t consumer0_active =
        codec_ctl.layout.Active(true, 0);
    const gf::Fp3 saved_consumer0_active =
        joined.columns[consumer0_active][0];
    joined.columns[consumer0_active][0] =
        gf::Fp3::Zero();
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirCodecCtlV1(
            joined, proof_bus, codec_decoder,
            codec_ctl, &why));
    joined.columns[consumer0_active][0] =
        saved_consumer0_active;

    // Duplicating address zero into the second event is not a permutation.
    BOOST_REQUIRE_GT(codec_ctl.semantic_events, 1U);
    const uint32_t consumer0_value =
        codec_ctl.layout.Value(true, 0);
    const uint32_t consumer0_address =
        codec_ctl.layout.Address(true, 0);
    const uint32_t consumer1_value =
        codec_ctl.layout.Value(true, 1);
    const uint32_t consumer1_address =
        codec_ctl.layout.Address(true, 1);
    const gf::Fp3 saved_consumer0_address =
        joined.columns[consumer0_address][0];
    const gf::Fp3 saved_consumer1_value =
        joined.columns[consumer1_value][0];
    const gf::Fp3 saved_consumer1_address =
        joined.columns[consumer1_address][0];
    joined.columns[consumer1_value][0] =
        joined.columns[consumer0_value][0];
    joined.columns[consumer1_address][0] =
        joined.columns[consumer0_address][0];
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirCodecCtlV1(
            joined, proof_bus, codec_decoder,
            codec_ctl, &why));
    joined.columns[consumer1_value][0] =
        saved_consumer1_value;
    joined.columns[consumer1_address][0] =
        saved_consumer1_address;

    // A relabel is rejected even if the value is unchanged.
    joined.columns[consumer0_address][0] =
        gf::Add(
            joined.columns[consumer0_address][0],
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirCodecCtlV1(
            joined, proof_bus, codec_decoder,
            codec_ctl, &why));
    joined.columns[consumer0_address][0] =
        saved_consumer0_address;

    // An alpha forced onto a live denominator is fail-closed.
    auto zero_denominator_ctl = codec_ctl;
    zero_denominator_ctl.challenges.alpha1 =
        gf::Add(
            joined.columns[consumer0_address][0],
            gf::Mul(
                zero_denominator_ctl.challenges.gamma1,
                joined.columns[consumer0_value][0]));
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirCodecCtlV1(
            joined, proof_bus, codec_decoder,
            zero_denominator_ctl, &why));

    auto promoted_codec_ctl = codec_ctl;
    promoted_codec_ctl.
        consumer_values_sourced_from_remote_chips =
            true;
    promoted_codec_ctl.recursively_consumed = true;
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirCodecCtlV1(
            joined, proof_bus, codec_decoder,
            promoted_codec_ctl, &why));

    auto removed_codec_ctl_constraint =
        std::move(
            joined.combined.constraints.back());
    joined.combined.constraints.pop_back();
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirCodecCtlV1(
            joined, proof_bus, codec_decoder,
            codec_ctl, &why));
    joined.combined.constraints.push_back(
        std::move(removed_codec_ctl_constraint));

    const fp::NormalizedAlgAirRemoteExportAttachmentV1
        remote_exports =
            fp::AttachNormalizedAlgAirRemoteExportsV1(
                joined, migrated.child.proof,
                codec_decoder, codec_ctl);
    BOOST_REQUIRE_MESSAGE(
        remote_exports.valid,
        remote_exports.note);
    BOOST_CHECK_GT(remote_exports.remote_events, 0U);
    BOOST_CHECK_GT(
        remote_exports.hash_opening_value_events,
        0U);
    BOOST_CHECK_GT(
        remote_exports.query_index_events, 0U);
    BOOST_CHECK_GT(
        remote_exports.authentication_path_events,
        0U);
    BOOST_CHECK_GT(remote_exports.root_events, 0U);
    BOOST_CHECK_GT(
        remote_exports.fold_value_events, 0U);
    BOOST_CHECK_GT(
        remote_exports.deep_tokens_remaining, 0U);
    BOOST_CHECK_GT(
        remote_exports.scheduler_tokens_remaining,
        0U);
    BOOST_CHECK(
        remote_exports.literal_same_row_aliases);
    BOOST_CHECK(
        remote_exports.
            every_direct_opening_query_path_root_fold_owned);
    BOOST_CHECK(
        remote_exports.
            dual_rational_identity_terminal_zero);
    BOOST_CHECK(remote_exports.denominator_nonzero);
    BOOST_CHECK(
        !remote_exports.
            derived_deep_inputs_remote_owned);
    BOOST_CHECK(
        !remote_exports.
            every_codec_consumer_remote_owned);
    BOOST_CHECK(
        !remote_exports.
            complete_fiat_shamir_replay_in_parent);
    BOOST_CHECK(!remote_exports.recursively_consumed);
    BOOST_REQUIRE_EQUAL(
        remote_exports.residuals.size(), 4U);
    BOOST_CHECK_EQUAL(
        remote_exports.added_columns, 338U);
    BOOST_CHECK_EQUAL(
        remote_exports.added_constraints, 86U);
    BOOST_CHECK_EQUAL(
        joined.combined.n_columns, 2526U);
    BOOST_CHECK_EQUAL(
        joined.combined.constraints.size(), 2199U);
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedAlgAirRemoteExportsV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports, &why),
        why);

    uint32_t first_remote_row =
        joined.combined.n_rows;
    uint32_t first_remote_port = 0;
    for (uint32_t row = 0;
         row < joined.combined.n_rows &&
         first_remote_row ==
             joined.combined.n_rows;
         ++row) {
        for (uint32_t port = 0;
             port <
                 fp::NormalizedAlgAirCodecCtlLayout::
                     kPorts;
             ++port) {
            if (!gf::IsZero(
                    joined.columns[
                        remote_exports.layout.bus.Active(
                            false, port)][row])) {
                first_remote_row = row;
                first_remote_port = port;
                break;
            }
        }
    }
    BOOST_REQUIRE_LT(
        first_remote_row,
        joined.combined.n_rows);
    const uint32_t first_remote_value =
        remote_exports.layout.bus.Value(
            false, first_remote_port);
    const uint32_t first_remote_address =
        remote_exports.layout.bus.Address(
            false, first_remote_port);
    const gf::Fp3 saved_remote_value =
        joined.columns[first_remote_value]
                      [first_remote_row];
    const gf::Fp3 saved_remote_address =
        joined.columns[first_remote_address]
                      [first_remote_row];
    joined.columns[first_remote_value]
                  [first_remote_row] =
        gf::Add(
            saved_remote_value,
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirRemoteExportsV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports, &why));
    joined.columns[first_remote_value]
                  [first_remote_row] =
        saved_remote_value;
    joined.columns[first_remote_address]
                  [first_remote_row] =
        gf::Add(
            saved_remote_address,
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirRemoteExportsV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports, &why));
    joined.columns[first_remote_address]
                  [first_remote_row] =
        saved_remote_address;

    auto zero_remote_denominator = remote_exports;
    zero_remote_denominator.challenges.alpha1 =
        gf::Add(
            saved_remote_address,
            gf::Mul(
                zero_remote_denominator.
                    challenges.gamma1,
                saved_remote_value));
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirRemoteExportsV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            zero_remote_denominator, &why));

    const fp::NormalizedDeepDerivationPlanV1
        deep64_plan =
            fp::AssessNormalizedDeepDerivation64PlanV1(
                migrated.child.proof,
                joined.combined.n_rows,
                joined.combined.n_columns);
    BOOST_REQUIRE_MESSAGE(
        deep64_plan.valid, deep64_plan.note);
    BOOST_CHECK_EQUAL(deep64_plan.ports, 64U);
    BOOST_CHECK_EQUAL(
        deep64_plan.query_item_sites,
        uint64_t{
            migrated.child.proof.batch.queries.size()} *
            migrated.child.proof.batch.column_len.size());
    BOOST_CHECK_EQUAL(
        deep64_plan.added_columns, 9751U);
    BOOST_CHECK_EQUAL(
        deep64_plan.final_parent_columns, 12277U);
    BOOST_CHECK_LE(
        deep64_plan.active_rows,
        joined.combined.n_rows);
    BOOST_CHECK(
        deep64_plan.shared_z_power_tables);
    BOOST_CHECK(
        deep64_plan.per_query_x_power_table);
    BOOST_CHECK(
        deep64_plan.shift_binary_accumulators);
    BOOST_CHECK(
        deep64_plan.lambda_item_recurrence);
    BOOST_CHECK(
        deep64_plan.
            input_multiplicity_logup_required);
    BOOST_CHECK(
        deep64_plan.output_logup_required);
    BOOST_CHECK(deep64_plan.row_cap_supported);
    BOOST_CHECK(deep64_plan.column_cap_supported);
    BOOST_CHECK(!deep64_plan.executable);

    // Endpoint 28 now has an executable standalone local-AIR pilot.  It is
    // deliberately not promoted to recursive/consensus closure: the
    // decoder aliases and unified-root terminal edges remain explicit.
    const fp::NormalizedDeepDerivationAttachmentV1
        deep_pilot =
            fp::BuildNormalizedDeepDerivationPilotV1(
                migrated.child.proof, 1);
    BOOST_REQUIRE_MESSAGE(
        deep_pilot.valid, deep_pilot.note);
    BOOST_CHECK_EQUAL(
        deep_pilot.added_columns,
        fp::NormalizedDeepDerivationLayoutV1{1}.End());
    BOOST_CHECK_EQUAL(deep_pilot.added_columns, 553U);
    BOOST_CHECK_GT(deep_pilot.added_constraints, 0U);
    BOOST_CHECK_EQUAL(deep_pilot.violations, 0U);
    BOOST_CHECK(
        deep_pilot.shared_z1_z2_square_tables);
    BOOST_CHECK(
        deep_pilot.parameterized_query_x_table);
    BOOST_CHECK(
        deep_pilot.shift_bits_and_three_products);
    BOOST_CHECK(
        deep_pilot.lambda_v_inverse_recurrences);
    BOOST_CHECK(
        deep_pilot.input_logup_terminal_zero);
    BOOST_CHECK(
        deep_pilot.read_logup_terminal_zero);
    BOOST_CHECK(
        deep_pilot.output_logup_terminal_zero);
    BOOST_CHECK(deep_pilot.denominator_nonzero);
    BOOST_CHECK(deep_pilot.witness_built);
    BOOST_CHECK(
        !deep_pilot.full_64_port_relation_closed);
    BOOST_CHECK(!deep_pilot.executable);
    BOOST_CHECK_EQUAL(
        deep_pilot.recursive_endpoints_consumed, 0U);
    BOOST_CHECK_EQUAL(
        deep_pilot.recursive_roles_consumed, 0U);
    BOOST_CHECK(!deep_pilot.recursively_consumed);
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedDeepDerivationPilotV1(
            migrated.child.proof,
            deep_pilot, &why),
        why);
    BOOST_CHECK_EQUAL(
        fp::NormalizedDeepDerivationLayoutV1{64}.End(),
        9751U);

    auto bad_z_square = deep_pilot;
    bad_z_square.columns[
        bad_z_square.layout.shared.Z1Square(1)][0] =
        gf::Add(
            bad_z_square.columns[
                bad_z_square.layout.shared
                    .Z1Square(1)][0],
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedDeepDerivationPilotV1(
            migrated.child.proof,
            bad_z_square, &why));

    auto bad_shift_bit = deep_pilot;
    const auto deep_port =
        bad_shift_bit.layout.Port(0);
    bad_shift_bit.columns[
        deep_port.ShiftBit(0)][0] =
        gf::Add(
            bad_shift_bit.columns[
                deep_port.ShiftBit(0)][0],
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedDeepDerivationPilotV1(
            migrated.child.proof,
            bad_shift_bit, &why));

    auto bad_lambda = deep_pilot;
    BOOST_REQUIRE_GT(
        bad_lambda.active_derivation_rows, 1U);
    bad_lambda.columns[
        deep_port.lambda_power][1] =
        gf::Add(
            bad_lambda.columns[
                deep_port.lambda_power][1],
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedDeepDerivationPilotV1(
            migrated.child.proof,
            bad_lambda, &why));

    auto bad_inverse = deep_pilot;
    bad_inverse.columns[deep_port.invd1][0] =
        gf::Add(
            bad_inverse.columns[
                deep_port.invd1][0],
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedDeepDerivationPilotV1(
            migrated.child.proof,
            bad_inverse, &why));

    auto bad_input_bus = deep_pilot;
    bad_input_bus.columns[
        bad_input_bus.layout.input_bus.Value(
            false, 0)][0] =
        gf::Add(
            bad_input_bus.columns[
                bad_input_bus.layout.input_bus.Value(
                    false, 0)][0],
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedDeepDerivationPilotV1(
            migrated.child.proof,
            bad_input_bus, &why));

    auto bad_output_bus = deep_pilot;
    bad_output_bus.columns[
        bad_output_bus.layout.output_bus.Value(
            true, 0)][0] =
        gf::Add(
            bad_output_bus.columns[
                bad_output_bus.layout.output_bus.Value(
                    true, 0)][0],
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedDeepDerivationPilotV1(
            migrated.child.proof,
            bad_output_bus, &why));

    auto promoted_deep = deep_pilot;
    promoted_deep.full_64_port_relation_closed = true;
    promoted_deep.executable = true;
    promoted_deep.recursive_endpoints_consumed = 1;
    promoted_deep.recursive_roles_consumed = 1;
    promoted_deep.recursively_consumed = true;
    BOOST_CHECK(
        !fp::ValidateNormalizedDeepDerivationPilotV1(
            migrated.child.proof,
            promoted_deep, &why));

    const auto invalid_two_port =
        fp::BuildNormalizedDeepDerivationPilotV1(
            migrated.child.proof, 2);
    BOOST_CHECK(!invalid_two_port.valid);

    const fp::NormalizedDeep64IntegrationV1
        deep64_integration =
            fp::BuildNormalizedDeep64IntegrationV1(
                joined, migrated.child.proof,
                codec_decoder, codec_ctl,
                remote_exports);
    BOOST_REQUIRE_MESSAGE(
        deep64_integration.valid,
        deep64_integration.note);
    BOOST_CHECK_EQUAL(
        deep64_integration.ports, 64U);
    BOOST_CHECK_EQUAL(
        deep64_integration.physical_port_records,
        uint64_t{
            migrated.child.proof.batch.queries.size()} *
            64);
    BOOST_CHECK_EQUAL(
        deep64_integration.active_port_records,
        uint64_t{
            migrated.child.proof.batch.queries.size()} *
            migrated.child.proof.batch.column_len.size());
    BOOST_CHECK_EQUAL(
        deep64_integration.canonical_deep_tokens,
        3 *
                migrated.child.proof.batch
                    .column_len.size() +
            5);
    BOOST_CHECK(
        deep64_integration.
            canonical_decoder_input_table_bound);
    BOOST_CHECK(
        deep64_integration.
            current_opening_values_literal_bound);
    BOOST_CHECK(
        deep64_integration.
            query_indices_literal_bound);
    BOOST_CHECK(
        deep64_integration.
            selected_fold_openings_literal_bound);
    BOOST_CHECK(
        deep64_integration.
            root_path_fold_remote_bus_preserved);
    BOOST_CHECK(
        deep64_integration.
            shared_power_tables_checked);
    BOOST_CHECK(
        deep64_integration.
            all_64_ports_structurally_constrained);
    BOOST_CHECK(
        deep64_integration.
            all_three_logup_terminals_zero);
    for (const auto& logup :
         deep64_integration.logup) {
        BOOST_CHECK(logup.valid);
        BOOST_CHECK(
            logup.commit_then_challenge);
        BOOST_CHECK(
            logup.denominator_nonzero);
        BOOST_CHECK(logup.terminal_zero);
        BOOST_CHECK(
            gf::IsZero(logup.terminal1));
        BOOST_CHECK(
            gf::IsZero(logup.terminal2));
        BOOST_CHECK_EQUAL(
            logup.producer_multiplicity,
            logup.consumer_multiplicity);
    }
    BOOST_CHECK(
        deep64_integration.
            local_endpoint_executable);
    BOOST_CHECK(deep64_integration.executable);
    BOOST_CHECK_EQUAL(
        deep64_integration.
            recursive_endpoints_consumed,
        0U);
    BOOST_CHECK_EQUAL(
        deep64_integration.
            recursive_roles_consumed,
        0U);
    BOOST_CHECK(
        !deep64_integration.
            recursively_consumed);
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedDeep64IntegrationV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports,
            deep64_integration, &why),
        why);

    auto bad_deep64_port =
        deep64_integration;
    BOOST_REQUIRE(
        !bad_deep64_port.port_witness.empty());
    bad_deep64_port.port_witness[0].x =
        gf::Add(
            bad_deep64_port.port_witness[0].x,
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedDeep64IntegrationV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports,
            bad_deep64_port, &why));

    auto bad_deep64_address =
        deep64_integration;
    ++bad_deep64_address.port_witness[0]
          .source_address[0];
    BOOST_CHECK(
        !fp::ValidateNormalizedDeep64IntegrationV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports,
            bad_deep64_address, &why));

    auto bad_deep64_terminal =
        deep64_integration;
    bad_deep64_terminal.logup[0].terminal1 =
        gf::Fp3::One();
    BOOST_CHECK(
        !fp::ValidateNormalizedDeep64IntegrationV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports,
            bad_deep64_terminal, &why));

    auto false_recursive_deep64 =
        deep64_integration;
    false_recursive_deep64.
        recursive_endpoints_consumed = 1;
    false_recursive_deep64.
        recursive_roles_consumed = 1;
    false_recursive_deep64.
        recursively_consumed = true;
    BOOST_CHECK(
        !fp::ValidateNormalizedDeep64IntegrationV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports,
            false_recursive_deep64, &why));

    const auto first_deep_token =
        std::find_if(
            codec_decoder.map.semantic_tokens.begin(),
            codec_decoder.map.semantic_tokens.end(),
            [](const auto& token) {
                return token.owner ==
                    fp::NormalizedAlgAirCodecOwnerFamily::
                        Deep;
            });
    BOOST_REQUIRE(
        first_deep_token !=
        codec_decoder.map.semantic_tokens.end());
    constexpr uint32_t CODEC_TRANSCRIPT_BEGIN = 5;
    const uint32_t deep_token_row =
        (CODEC_TRANSCRIPT_BEGIN +
         first_deep_token->word_index) /
        fp::NormalizedAlgAirCodecCtlLayout::kPorts;
    const uint32_t deep_token_port =
        (CODEC_TRANSCRIPT_BEGIN +
         first_deep_token->word_index) %
        fp::NormalizedAlgAirCodecCtlLayout::kPorts;
    const uint32_t deep_token_value_column =
        codec_ctl.layout.Value(
            false, deep_token_port);
    const gf::Fp3 saved_deep_token_value =
        joined.columns[deep_token_value_column]
                      [deep_token_row];
    joined.columns[deep_token_value_column]
                  [deep_token_row] =
        gf::Add(
            saved_deep_token_value,
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedDeep64IntegrationV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports,
            deep64_integration, &why));
    joined.columns[deep_token_value_column]
                  [deep_token_row] =
        saved_deep_token_value;

    auto promoted_remote_exports = remote_exports;
    promoted_remote_exports.
        derived_deep_inputs_remote_owned = true;
    promoted_remote_exports.
        every_codec_consumer_remote_owned = true;
    promoted_remote_exports.recursively_consumed = true;
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirRemoteExportsV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            promoted_remote_exports, &why));

    auto removed_remote_constraint =
        std::move(
            joined.combined.constraints.back());
    joined.combined.constraints.pop_back();
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirRemoteExportsV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports, &why));
    joined.combined.constraints.push_back(
        std::move(removed_remote_constraint));

    const fp::NormalizedAlgAirSchedulerTokenAttachmentV1
        scheduler_tokens =
            fp::AttachNormalizedAlgAirSchedulerTokensV1(
                joined, migrated.child.proof,
                codec_decoder, codec_ctl,
                remote_exports);
    BOOST_REQUIRE_MESSAGE(
        scheduler_tokens.valid,
        scheduler_tokens.note);
    BOOST_CHECK_GT(
        scheduler_tokens.scheduler_tokens, 0U);
    BOOST_CHECK_GT(
        scheduler_tokens.shape_tokens, 0U);
    BOOST_CHECK_GT(
        scheduler_tokens.fold_schedule_tokens, 0U);
    BOOST_CHECK_GT(
        scheduler_tokens.query_schedule_tokens, 0U);
    BOOST_CHECK_GT(
        scheduler_tokens.path_length_tokens, 0U);
    BOOST_CHECK_EQUAL(
        scheduler_tokens.shape_tokens +
            scheduler_tokens.fold_schedule_tokens +
            scheduler_tokens.query_schedule_tokens +
            scheduler_tokens.path_length_tokens,
        scheduler_tokens.scheduler_tokens);
    BOOST_CHECK(
        scheduler_tokens.
            values_derived_from_public_program);
    BOOST_CHECK(
        scheduler_tokens.exact_scheduler_addresses);
    BOOST_CHECK(
        scheduler_tokens.every_scheduler_token_owned);
    BOOST_CHECK(
        scheduler_tokens.
            dual_rational_identity_terminal_zero);
    BOOST_CHECK(scheduler_tokens.denominator_nonzero);
    BOOST_CHECK_GT(
        scheduler_tokens.
            sha256d_challenge_outputs_remaining,
        0U);
    BOOST_CHECK_EQUAL(
        scheduler_tokens.
            sha256d_nonce_inputs_remaining,
        1U);
    BOOST_CHECK_EQUAL(
        scheduler_tokens.
            ctl_child_terminal_items_remaining,
        1U);
    BOOST_CHECK(
        !scheduler_tokens.
            complete_fiat_shamir_replay_in_parent);
    BOOST_CHECK(
        !scheduler_tokens.
            ctl_commitment_sourced_from_child_verifier);
    BOOST_CHECK(!scheduler_tokens.recursively_consumed);
    BOOST_REQUIRE_EQUAL(
        scheduler_tokens.residuals.size(), 3U);
    BOOST_CHECK_EQUAL(
        scheduler_tokens.added_columns, 90U);
    BOOST_CHECK_EQUAL(
        scheduler_tokens.added_constraints, 70U);
    BOOST_CHECK_EQUAL(
        joined.combined.n_columns, 2616U);
    BOOST_CHECK_EQUAL(
        joined.combined.constraints.size(), 2269U);
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedAlgAirSchedulerTokensV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports, scheduler_tokens,
            &why),
        why);

    const uint32_t scheduler_value0 =
        scheduler_tokens.layout.Value(false, 0);
    const uint32_t scheduler_address0 =
        scheduler_tokens.layout.Address(false, 0);
    const uint32_t scheduler_active0 =
        scheduler_tokens.layout.Active(false, 0);
    const uint32_t scheduler_value1 =
        scheduler_tokens.layout.Value(false, 1);
    const uint32_t scheduler_address1 =
        scheduler_tokens.layout.Address(false, 1);
    const gf::Fp3 saved_scheduler_value0 =
        joined.columns[scheduler_value0][0];
    const gf::Fp3 saved_scheduler_address0 =
        joined.columns[scheduler_address0][0];
    const gf::Fp3 saved_scheduler_active0 =
        joined.columns[scheduler_active0][0];
    const gf::Fp3 saved_scheduler_value1 =
        joined.columns[scheduler_value1][0];
    const gf::Fp3 saved_scheduler_address1 =
        joined.columns[scheduler_address1][0];

    // Omission.
    joined.columns[scheduler_active0][0] =
        gf::Fp3::Zero();
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirSchedulerTokensV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports, scheduler_tokens,
            &why));
    joined.columns[scheduler_active0][0] =
        saved_scheduler_active0;

    // Reordering two otherwise valid public-program tuples.
    joined.columns[scheduler_value0][0] =
        saved_scheduler_value1;
    joined.columns[scheduler_address0][0] =
        saved_scheduler_address1;
    joined.columns[scheduler_value1][0] =
        saved_scheduler_value0;
    joined.columns[scheduler_address1][0] =
        saved_scheduler_address0;
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirSchedulerTokensV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports, scheduler_tokens,
            &why));
    joined.columns[scheduler_value0][0] =
        saved_scheduler_value0;
    joined.columns[scheduler_address0][0] =
        saved_scheduler_address0;
    joined.columns[scheduler_value1][0] =
        saved_scheduler_value1;
    joined.columns[scheduler_address1][0] =
        saved_scheduler_address1;

    // Relabel.
    joined.columns[scheduler_address0][0] =
        gf::Add(
            saved_scheduler_address0,
            gf::Fp3::One());
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirSchedulerTokensV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports, scheduler_tokens,
            &why));
    joined.columns[scheduler_address0][0] =
        saved_scheduler_address0;

    auto promoted_scheduler = scheduler_tokens;
    promoted_scheduler.
        complete_fiat_shamir_replay_in_parent = true;
    promoted_scheduler.
        ctl_commitment_sourced_from_child_verifier =
            true;
    promoted_scheduler.recursively_consumed = true;
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirSchedulerTokensV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports, promoted_scheduler,
            &why));

    auto removed_scheduler_constraint =
        std::move(
            joined.combined.constraints.back());
    joined.combined.constraints.pop_back();
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirSchedulerTokensV1(
            joined, migrated.child.proof,
            codec_decoder, codec_ctl,
            remote_exports, scheduler_tokens,
            &why));
    joined.combined.constraints.push_back(
        std::move(removed_scheduler_constraint));

    const fp::NormalizedDeepDerivationPlanV1
        post_scheduler_deep64_plan =
            fp::AssessNormalizedDeepDerivation64PlanV1(
                migrated.child.proof,
                joined.combined.n_rows,
                joined.combined.n_columns);
    BOOST_REQUIRE_MESSAGE(
        post_scheduler_deep64_plan.valid,
        post_scheduler_deep64_plan.note);
    BOOST_CHECK_EQUAL(
        post_scheduler_deep64_plan.
            final_parent_columns,
        12367U);

    const gf::Fp3 saved_root_limb =
        joined.columns[
            terminal_layout.RootLimb(0)][0];
    joined.columns[
        terminal_layout.RootLimb(0)][0] =
        gf::Add(
            saved_root_limb,
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined, joined.columns),
        0U);
    joined.columns[
        terminal_layout.RootLimb(0)][0] =
        saved_root_limb;

    fp::NormalizedRoleChildRegistry registry =
        fp::BuildCanonicalNormalizedRoleChildRegistrySchedule();
    BOOST_REQUIRE_EQUAL(registry.slots.size(), 14U);
    BOOST_REQUIRE_MESSAGE(
        fp::InstallNormalizedRoleChildSlot(
            registry, execution.slot, &why),
        why);
    const auto partial =
        fp::AssessNormalizedRoleChildRegistry(registry);
    BOOST_CHECK(partial.canonical_order_and_intervals);
    BOOST_CHECK(partial.normalized_v1_only);
    BOOST_CHECK_EQUAL(partial.scheduled_roles, 14U);
    BOOST_CHECK_EQUAL(
        partial.normalized_v1_bound_roles, 1U);
    BOOST_CHECK_EQUAL(
        partial.missing_or_invalid_roles, 13U);
    BOOST_CHECK_EQUAL(
        partial.recursively_consumed_roles, 0U);
    BOOST_CHECK(!partial.binding_complete);
    BOOST_CHECK(
        !partial.recursive_consumption_complete);
    BOOST_CHECK(registry.registry_commitment.IsNull());
    BOOST_CHECK(
        !fp::VerifyNormalizedRoleChildRegistryBinding(
            registry, &why));

    auto legacy_mixed = execution.slot;
    legacy_mixed.normalized_semantic_root =
        aq::AirCommittedValuesRoot<gf::Fp3>(
            migrated.columns[
                rc::kRCStage3CoupledBankOutput],
            migrated.source_pin.n_coeffs);
    legacy_mixed.slot_commitment =
        fp::ComputeNormalizedRoleChildSlotCommitment(
            legacy_mixed);
    BOOST_CHECK(legacy_mixed.slot_commitment.IsNull());
    BOOST_CHECK(
        !fp::InstallNormalizedRoleChildSlot(
            registry, legacy_mixed, &why));

    auto reordered =
        fp::BuildCanonicalNormalizedRoleChildRegistrySchedule();
    std::swap(reordered.slots[0], reordered.slots[1]);
    const auto reordered_audit =
        fp::AssessNormalizedRoleChildRegistry(
            reordered);
    BOOST_CHECK(
        !reordered_audit.canonical_order_and_intervals);
}

BOOST_AUTO_TEST_CASE(
    coupled_bank_endpoint28_projection_bridge_v1_fail_closed)
{
    const CoupledBankChild migrated =
        BuildCoupledBankChild();
    fp::NormalizedCoupledBankCtlProjectionBridgeProofV1
        semantic_proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        fp::ProveNormalizedCoupledBankCtlProjectionBridgeV1(
            migrated.source_pin,
            migrated.columns,
            migrated.child.seed,
            semantic_proof,
            &why),
        why);
    BOOST_CHECK(
        !semantic_proof.output_projection_root.IsNull());
    BOOST_CHECK(
        !semantic_proof.proof_commitment.IsNull());
    BOOST_CHECK(
        !semantic_proof.terminal_bus_commitment.IsNull());
    BOOST_REQUIRE_EQUAL(
        semantic_proof.pins.size(), 2U);
    BOOST_CHECK_EQUAL(
        semantic_proof.pins[0].send_count,
        migrated.source_pin.logical_rows);
    BOOST_CHECK_EQUAL(
        semantic_proof.pins[1].receive_count,
        migrated.source_pin.logical_rows);

    fp::NormalizedRoleChildRegistry registry =
        fp::BuildCanonicalNormalizedRoleChildRegistrySchedule();
    BOOST_REQUIRE_GT(registry.slots.size(), 6U);
    fp::NormalizedRoleChildSlot slot =
        registry.slots[6];
    BOOST_REQUIRE(
        slot.role ==
        rc::RCStage3RelationRole::CoupledBank);
    slot.statement_commitment =
        migrated.source_pin.statement_commitment;
    slot.program_table_commitment =
        rc::constraint_bytecode::CommitProgramTable(
            migrated.table);
    slot.child_trace_row_root =
        semantic_proof.pins[0].trace_commitment;
    slot.child_proof_commitment =
        semantic_proof.proof_commitment;
    slot.terminal_bus_commitment =
        semantic_proof.terminal_bus_commitment;
    slot.normalized_semantic_root =
        fp::ComputeNormalizedSemanticRootV1(slot);
    slot.slot_commitment =
        fp::ComputeNormalizedRoleChildSlotCommitment(
            slot);
    BOOST_REQUIRE(!slot.slot_commitment.IsNull());

    fp::FoldBusComposition composition =
        fp::BuildFoldBusComposition(
            migrated.child.cs,
            migrated.child.proof,
            migrated.child.seed);
    BOOST_REQUIRE_MESSAGE(
        composition.valid, composition.note);
    const auto sponge =
        fp::AttachNormalizedSemanticRootSpongeV1(
            composition, slot);
    BOOST_REQUIRE_MESSAGE(
        sponge.valid, sponge.note);

    const auto audit =
        fp::VerifyNormalizedCoupledBankCtlProjectionBridgeV1(
            migrated.source_pin,
            semantic_proof,
            migrated.child.seed,
            composition, slot, sponge);
    BOOST_REQUIRE_MESSAGE(
        audit.valid, audit.note);
    BOOST_CHECK(audit.exact_tuple_schedule);
    BOOST_CHECK(
        audit.producer_relation_output_same_trace);
    BOOST_CHECK(
        audit.producer_split_rap_verified);
    BOOST_CHECK(
        audit.mirror_projection_root_verified);
    BOOST_CHECK(
        audit.mirror_ctl_child_verified);
    BOOST_CHECK(
        audit.shared_post_commit_challenges);
    BOOST_CHECK(
        audit.dual_logup_terminal_equality);
    BOOST_CHECK(
        audit.projection_self_consistency_verified);
    BOOST_CHECK(
        !audit.registered_consumer_relation_bound);
    BOOST_CHECK(
        !audit.producer_registered_roots_bound);
    BOOST_CHECK(
        !audit.signed_output_to_u8_mapping_verified);
    BOOST_CHECK(!audit.all_pages_aggregated);
    BOOST_CHECK(
        !audit.
            projection_child_soundness_at_least_100_bits);
    BOOST_CHECK(
        !audit.native_cross_proof_semantic_closure);
    BOOST_CHECK(!audit.production_semantic_closure);
    BOOST_CHECK(
        audit.
            proof_and_projection_bound_in_semantic_slot);
    BOOST_CHECK(
        audit.semantic_root_lanes_verified);
    BOOST_CHECK(
        !audit.
            complete_sha_fiat_shamir_replay_in_parent);
    BOOST_CHECK(
        !audit.all_child_verifiers_execute_in_parent);
    BOOST_CHECK(!audit.endpoint_promoted);
    BOOST_CHECK(!audit.authority);
    BOOST_CHECK_EQUAL(
        audit.recursive_endpoints_consumed, 0U);
    BOOST_CHECK_EQUAL(
        audit.recursive_roles_consumed, 0U);
    BOOST_REQUIRE_EQUAL(
        audit.residuals.size(), 7U);
    BOOST_CHECK(
        audit.residuals[0].find(
            "registered_endpoint29") !=
        std::string::npos);

    fp::NormalizedCoupledBankCtlProjectionBridgeProofV1
        free_seed_proof;
    BOOST_CHECK(
        !fp::ProveNormalizedCoupledBankCtlProjectionBridgeV1(
            migrated.source_pin,
            migrated.columns,
            Seed(0xd0),
            free_seed_proof,
            &why));

    auto bad_projection = semantic_proof;
    bad_projection.output_projection_root =
        Seed(0xd1);
    BOOST_CHECK(
        !fp::VerifyNormalizedCoupledBankCtlProjectionBridgeV1(
             migrated.source_pin,
             bad_projection,
             migrated.child.seed,
             composition, slot, sponge)
             .valid);

    auto bad_multiplicity = semantic_proof;
    bad_multiplicity.mirror_schedule
        .events[0].multiplicity = 1;
    BOOST_CHECK(
        !fp::VerifyNormalizedCoupledBankCtlProjectionBridgeV1(
             migrated.source_pin,
             bad_multiplicity,
             migrated.child.seed,
             composition, slot, sponge)
             .valid);

    auto bad_order = semantic_proof;
    BOOST_REQUIRE_EQUAL(
        bad_order.producer_schedule.events.size(),
        2U);
    std::swap(
        bad_order.producer_schedule.events[0],
        bad_order.producer_schedule.events[1]);
    BOOST_CHECK(
        !fp::VerifyNormalizedCoupledBankCtlProjectionBridgeV1(
             migrated.source_pin,
             bad_order,
             migrated.child.seed,
             composition, slot, sponge)
             .valid);

    auto bad_producer = semantic_proof;
    BOOST_REQUIRE_EQUAL(
        bad_producer.producer_proof.batch
            .groups.size(),
        3U);
    bad_producer.producer_proof.batch
        .groups[0].row_commit.root[0] =
        gf::Add(
            bad_producer.producer_proof.batch
                .groups[0].row_commit.root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !fp::VerifyNormalizedCoupledBankCtlProjectionBridgeV1(
             migrated.source_pin,
             bad_producer,
             migrated.child.seed,
             composition, slot, sponge)
             .valid);

    auto stale_slot = slot;
    stale_slot.terminal_bus_commitment =
        Seed(0xd2);
    stale_slot.normalized_semantic_root =
        fp::ComputeNormalizedSemanticRootV1(
            stale_slot);
    stale_slot.slot_commitment =
        fp::ComputeNormalizedRoleChildSlotCommitment(
            stale_slot);
    BOOST_CHECK(
        !fp::VerifyNormalizedCoupledBankCtlProjectionBridgeV1(
             migrated.source_pin,
             semantic_proof,
             migrated.child.seed,
             composition, stale_slot, sponge)
             .valid);
}

BOOST_AUTO_TEST_CASE(
    normalized_terminal_transcript_maps_all_roles_and_endpoints)
{
    const rc::RCStage3RelationClosureV1 closure =
        CompleteSyntheticRelationClosure();
    fp::NormalizedTerminalTranscriptV1 transcript;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        fp::BuildNormalizedTerminalTranscriptV1(
            closure, transcript, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        transcript.roles.size(), 14U);
    BOOST_REQUIRE_EQUAL(
        transcript.endpoints.size(), 52U);
    const auto audit =
        fp::AssessNormalizedTerminalTranscriptV1(
            transcript);
    BOOST_CHECK(audit.canonical_role_order);
    BOOST_CHECK(audit.canonical_endpoint_order);
    BOOST_CHECK(
        audit.all_terminal_commitments_recomputed);
    BOOST_CHECK(audit.source_closure_binding);
    BOOST_CHECK(audit.binding_complete);
    BOOST_CHECK_EQUAL(
        audit.recursively_child_proof_owned_roles,
        0U);
    BOOST_CHECK_EQUAL(
        audit.recursively_child_proof_owned_endpoints,
        0U);
    BOOST_CHECK(
        !audit.recursive_consumption_complete);
    BOOST_CHECK(
        audit.blocker.find(
            "52_endpoint_children") !=
        std::string::npos);

    // The normalized parent uses a vertical transcript: 58 witness cells
    // and 58 verifier-owned expected cells cover all records in 69 rows.
    fp::FoldBusComposition composition;
    composition.valid = true;
    composition.combined.n_rows = 128;
    composition.combined.n_columns = 1;
    composition.columns.assign(
        1, std::vector<gf::Fp3>(
               composition.combined.n_rows,
               gf::Fp3::Zero()));
    const auto attached =
        fp::AttachNormalizedTerminalTranscriptV1(
            composition, transcript);
    BOOST_REQUIRE_MESSAGE(
        attached.valid, attached.blocker);
    BOOST_CHECK(attached.ordered_coverage);
    BOOST_CHECK(
        attached.transcript_commitment_bound);
    BOOST_CHECK_EQUAL(
        attached.locally_constrained_roles, 14U);
    BOOST_CHECK_EQUAL(
        attached.locally_constrained_endpoints, 52U);
    BOOST_CHECK_EQUAL(
        attached.
            recursively_child_proof_owned_roles,
        0U);
    BOOST_CHECK_EQUAL(
        attached.
            recursively_child_proof_owned_endpoints,
        0U);
    BOOST_CHECK_EQUAL(
        attached.equality_constraints,
        fp::NormalizedTerminalTranscriptLayout::
            kCells);
    BOOST_CHECK_EQUAL(
        fp::NormalizedTerminalTranscriptLayout::
            kRequiredRows,
        69U);
    BOOST_CHECK_EQUAL(
        composition.combined.n_columns,
        1U + 2U *
            fp::NormalizedTerminalTranscriptLayout::
                kCells);
    BOOST_CHECK_EQUAL(composition.violations, 0U);

    auto changed_witness = composition.columns;
    changed_witness[
        attached.layout.Witness(
            attached.layout.DigestCell(2, 0))][0] =
        gf::Add(
            changed_witness[
                attached.layout.Witness(
                    attached.layout.DigestCell(
                        2, 0))][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            composition.combined,
            changed_witness),
        0U);

    // Omission, reorder and endpoint substitution all fail even when the
    // attacker consistently recomputes the enclosing host-side hashes.
    auto omitted = closure;
    omitted.roles[0].endpoints.pop_back();
    omitted.roles[0].endpoint_multiproof_root =
        rc::ComputeRCStage3RelationRoleMultiproofRoot(
            omitted.roles[0]);
    omitted.closure_commitment =
        rc::ComputeRCStage3RelationClosureCommitment(
            omitted);
    fp::NormalizedTerminalTranscriptV1 rejected;
    BOOST_CHECK(
        !fp::BuildNormalizedTerminalTranscriptV1(
            omitted, rejected, &why));

    auto reordered_endpoint = closure;
    std::swap(
        reordered_endpoint.roles[1].endpoints[0],
        reordered_endpoint.roles[1].endpoints[1]);
    reordered_endpoint.roles[1].
        endpoint_multiproof_root =
        rc::ComputeRCStage3RelationRoleMultiproofRoot(
            reordered_endpoint.roles[1]);
    reordered_endpoint.closure_commitment =
        rc::ComputeRCStage3RelationClosureCommitment(
            reordered_endpoint);
    BOOST_CHECK(
        !fp::BuildNormalizedTerminalTranscriptV1(
            reordered_endpoint, rejected, &why));

    auto substituted = closure;
    substituted.roles[2].endpoints[0].endpoint =
        rc::RCStage3RelationEndpoint::
            CoupledDigestValue;
    substituted.roles[2].endpoint_multiproof_root =
        rc::ComputeRCStage3RelationRoleMultiproofRoot(
            substituted.roles[2]);
    substituted.closure_commitment =
        rc::ComputeRCStage3RelationClosureCommitment(
            substituted);
    BOOST_CHECK(
        !fp::BuildNormalizedTerminalTranscriptV1(
            substituted, rejected, &why));

    auto reordered_role = closure;
    std::swap(
        reordered_role.roles[0],
        reordered_role.roles[1]);
    reordered_role.closure_commitment =
        rc::ComputeRCStage3RelationClosureCommitment(
            reordered_role);
    BOOST_CHECK(
        !fp::BuildNormalizedTerminalTranscriptV1(
            reordered_role, rejected, &why));

    // A self-consistent transcript edit still cannot detach from the source
    // relation-closure commitment.
    auto detached = transcript;
    detached.endpoints[0].semantic_root =
        Seed(0xee);
    detached.endpoints[0].terminal_commitment =
        fp::ComputeNormalizedEndpointTerminalBusCommitment(
            detached.endpoints[0]);
    detached.roles[0].terminal_commitment =
        fp::ComputeNormalizedRoleTerminalBusCommitment(
            detached.roles[0], detached.endpoints);
    detached.transcript_commitment =
        fp::ComputeNormalizedTerminalTranscriptCommitment(
            detached);
    const auto detached_audit =
        fp::AssessNormalizedTerminalTranscriptV1(
            detached);
    BOOST_CHECK(
        !detached_audit.source_closure_binding);
    BOOST_CHECK(!detached_audit.binding_complete);
}

BOOST_AUTO_TEST_CASE(
    coupled_bank_8192x639_parent_streaming_round_trip)
{
    const CoupledBankChild migrated =
        BuildCoupledBankChild();
    fp::FoldBusComposition joined =
        fp::BuildFoldBusComposition(
            migrated.child.cs,
            migrated.child.proof,
            migrated.child.seed);
    BOOST_REQUIRE_MESSAGE(joined.valid, joined.note);
    const fp::BytecodeInterpreterAttachment interpreter =
        fp::AttachConstraintBytecodeInterpreter(
            joined, migrated.table);
    BOOST_REQUIRE_MESSAGE(
        interpreter.valid, interpreter.note);
    BOOST_REQUIRE_EQUAL(joined.combined.n_rows, 8192U);
    BOOST_REQUIRE_EQUAL(joined.combined.n_columns, 640U);
    BOOST_REQUIRE_EQUAL(
        joined.columns.size(),
        joined.combined.n_columns);

    const uint256 parent_seed = Seed(0x91);
    const auto prove_start =
        std::chrono::steady_clock::now();
    const auto proved =
        aq::AirQuotientProveRows(
            joined.combined, joined.columns,
            parent_seed, {});
    const uint64_t prove_micros =
        static_cast<uint64_t>(
            std::chrono::duration_cast<
                std::chrono::microseconds>(
                std::chrono::steady_clock::now() -
                prove_start)
                .count());
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact,
        proved.note);

    const auto verify_start =
        std::chrono::steady_clock::now();
    std::string verify_why;
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRows(
            joined.combined, proved.proof,
            parent_seed, &verify_why),
        verify_why);
    const uint64_t verify_micros =
        static_cast<uint64_t>(
            std::chrono::duration_cast<
                std::chrono::microseconds>(
                std::chrono::steady_clock::now() -
                verify_start)
                .count());

    // The streaming policy changes only prover memory behavior. Copy into
    // the ordinary Alg backend's identical proof container and require the
    // existing recursive consumer verifier to accept it.
    fp::AlgAirProof ordinary_view;
    ordinary_view.batch = proved.proof.batch;
    ordinary_view.next_openings =
        proved.proof.next_openings;
    ordinary_view.trace_commit =
        proved.proof.trace_commit;
    BOOST_REQUIRE_MESSAGE(
        (aq::AirQuotientVerify<
            gf::Fp3,
            aq::AirFriBackendAlg<gf::Fp3>>(
            joined.combined, ordinary_view,
            parent_seed, &verify_why)),
        verify_why);

    std::vector<unsigned char> batch;
    const size_t batch_bytes =
        rc::SerializeFri3AlgBatchProof(
            proved.proof.batch, batch);
    BOOST_REQUIRE_EQUAL(batch_bytes, batch.size());
    BOOST_REQUIRE_NE(batch_bytes, 0U);
    uint64_t proof_bytes =
        uint64_t{batch_bytes} + 32 + 4;
    for (const auto& paths :
         proved.proof.next_openings) {
        proof_bytes += 4;
        for (const auto& path : paths) {
            proof_bytes += 8;
            proof_bytes +=
                uint64_t{path.values.size()} *
                3 * sizeof(uint64_t);
            proof_bytes +=
                uint64_t{path.siblings.size()} *
                rc::alg_hash::kAlgHashDigestLen *
                sizeof(uint64_t);
        }
    }
    BOOST_CHECK_LE(
        batch_bytes, rc::kRCFriMaxProofBytesHard);
    BOOST_CHECK_EQUAL(
        proved.proof.batch.queries.size(), 192U);
    BOOST_CHECK_EQUAL(
        proved.proof.next_openings.size(), 192U);

    BOOST_TEST_MESSAGE(
        "streamed recursive parent: rows="
        << joined.combined.n_rows
        << " cols=" << joined.combined.n_columns
        << " constraints="
        << joined.combined.constraints.size()
        << " prove_us=" << prove_micros
        << " verify_us=" << verify_micros
        << " batch_bytes=" << batch_bytes
        << " estimated_air_proof_bytes="
        << proof_bytes);
}

// g2: EpisodeTileTree / EpisodeDigest hand-authored SHA-256 hash-kernel
// ProgramTables (see role_bytecode_tests) must agree with the child's native
// constraint metadata under the SAME AttachConstraintBytecodeInterpreter
// gate CoupledBank/EpisodeDigest header-target already use. At Q=192 the
// full 462-program kernel needs ~queries*(instructions+1) free parent rows
// (~1e6), far above a hash-opening-sized fold-bus parent — so the vertical
// interpreter is capacity-closed with bytecode_vertical_rows AFTER the
// metadata cross-check passes. Hierarchical row-budget planning (reusing
// PlanHierarchicalNarrowAggregation) shows the same ProgramTable CAN close
// under LDE/column caps when sharded across nodes; single-node pad still
// refuses. Does NOT flip kCompleteRecursiveFixedPointExecutable.
//
// Also measures NarrowBytecodePerPointJoinBudgetV1: P2 FS closure is consumed
// from the ledger, column projection stays narrow (<1024), and pad-to-fit is
// refused when projected LDE exceeds kRCFriMaxLdeLog2 (honest capacity-close).
BOOST_AUTO_TEST_CASE(
    episode_tiletree_and_digest_hash_kernel_attaches_via_fold_bus)
{
    const HonestChild hash_child = BuildHashKernelChild();
    const fp::FoldBusComposition base =
        fp::BuildFoldBusComposition(
            hash_child.cs, hash_child.proof, hash_child.seed);
    BOOST_REQUIRE_MESSAGE(base.valid, base.note);
    const auto& pi = base.hash.program.public_inputs;
    BOOST_REQUIRE_EQUAL(
        hash_child.cs.constraints.size(), 462U);
    BOOST_REQUIRE_EQUAL(
        pi.child_constraints.size(),
        hash_child.cs.constraints.size());

    for (const rc::RCStage3RelationRole role :
         {rc::RCStage3RelationRole::EpisodeTileTree,
          rc::RCStage3RelationRole::EpisodeDigest}) {
        rc::constraint_bytecode::ProgramTable table;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            rc::BuildRCStage3CoupledHashKernelProgramTable(
                role, table, &why),
            why);
        BOOST_CHECK(table.role == role);
        BOOST_REQUIRE_EQUAL(
            table.programs.size(),
            pi.child_constraints.size());
        BOOST_CHECK_EQUAL(table.current_width, pi.child_w);
        BOOST_CHECK_EQUAL(table.next_width, pi.child_w);

        uint32_t instructions = 0;
        for (uint32_t ordinal = 0;
             ordinal < table.programs.size(); ++ordinal) {
            BOOST_CHECK(
                table.programs[ordinal].kind ==
                pi.child_constraints[ordinal].kind);
            BOOST_CHECK_EQUAL(
                table.programs[ordinal].declared_degree,
                pi.child_constraints[ordinal].alg_degree);
            instructions += static_cast<uint32_t>(
                table.programs[ordinal].instructions.size());
        }
        const uint64_t rows_needed =
            uint64_t{pi.query_index.size()} *
            (uint64_t{instructions} + 1U);
        BOOST_REQUIRE_GT(rows_needed, base.combined.n_rows);
        BOOST_CHECK_EQUAL(
            fp::CountProgramTableInstructions(table),
            instructions);

        const fp::NarrowBytecodePerPointJoinBudgetV1 budget =
            fp::AssessNarrowBytecodePerPointJoinBudgetV1(
                base, table);
        BOOST_REQUIRE_MESSAGE(budget.valid, budget.note);
        BOOST_CHECK(budget.p2_fs_replay_closed);
        BOOST_CHECK(budget.projected_columns_narrow);
        BOOST_CHECK_EQUAL(budget.rows_needed, rows_needed);
        BOOST_CHECK(!budget.rows_fit_without_pad);
        BOOST_CHECK(
            budget.exact_quotient_degree_accounting);
        BOOST_CHECK_EQUAL(
            budget.projected_max_algebraic_degree,
            nr::kMeasuredNarrowMaxAlgebraicDegree);
        BOOST_CHECK_EQUAL(
            budget.projected_quotient_len,
            uint64_t{
                nr::kMeasuredNarrowMaxAlgebraicDegree -
                1} *
                (budget.projected_trace_rows - 1));
        BOOST_CHECK_GT(
            budget.projected_coefficient_rows,
            budget.projected_trace_rows);
        BOOST_CHECK_EQUAL(
            budget.projected_lde,
            budget.projected_coefficient_rows *
                rc::kRCFriBlowup);
        BOOST_CHECK(budget.capacity_closed);
        BOOST_CHECK(!budget.projected_lde_supported);
        BOOST_CHECK(!budget.single_node_fri_representable);
        // Hierarchical planner closes the same table under budgets.
        BOOST_CHECK(budget.hierarchical_attach_planned);
        BOOST_CHECK(budget.hierarchical_attach_fits);
        BOOST_CHECK_GE(budget.hierarchical_depth, 2U);
        BOOST_CHECK_GE(budget.hierarchical_node_count, 3U);
        BOOST_TEST_MESSAGE(budget.note);

        const fp::NarrowBytecodeHierarchicalAttachPlanV1 hier =
            fp::PlanNarrowBytecodeHierarchicalAttachV1(
                table,
                static_cast<uint32_t>(pi.query_index.size()));
        BOOST_REQUIRE_MESSAGE(hier.valid, hier.note);
        BOOST_CHECK(!hier.single_node_fits);
        BOOST_CHECK(hier.hierarchical_fits);
        BOOST_CHECK(hier.all_programs_covered);
        for (const auto& node : hier.hierarchy.nodes) {
            BOOST_CHECK_MESSAGE(
                node.shape.representable, node.label);
            BOOST_CHECK_LE(
                node.shape.n_lde, uint32_t{1} << 24);
        }
        BOOST_TEST_MESSAGE(hier.note);

        fp::FoldBusComposition joined = base;
        const fp::BytecodeInterpreterAttachment
            interpreter =
                fp::AttachConstraintBytecodeInterpreter(
                    joined, table);
        BOOST_CHECK(!interpreter.valid);
        BOOST_CHECK(
            interpreter.note.find(
                "bytecode_child_constraint_metadata") ==
            std::string::npos);
        BOOST_REQUIRE_MESSAGE(
            interpreter.note.find("bytecode_vertical_rows") !=
                std::string::npos,
            interpreter.note);
        BOOST_CHECK(
            interpreter.note.find(
                "needed=" + std::to_string(rows_needed)) !=
            std::string::npos);
        BOOST_CHECK(
            interpreter.note.find("hier_fits=1") !=
            std::string::npos);

        // Pad refuses when LDE would exceed the FRI domain cap — same
        // capacity-close the budget assessor reports. Hierarchy note is
        // recorded so callers do not try to invent single-node headroom.
        fp::FoldBusComposition padded = base;
        BOOST_CHECK(!fp::PadFoldBusFreeRowsForBytecode(
            padded, rows_needed, &table, &why));
        BOOST_CHECK(
            why.find("bytecode_pad_lde_over_cap") !=
                std::string::npos ||
            why.find("bytecode_pad_fri_over_cap") !=
                std::string::npos);
        BOOST_CHECK(
            why.find("hier_fits=1") != std::string::npos);

        // Forgery: dropping one program fails the child-constraint table
        // shape check before any vertical row budget is considered.
        rc::constraint_bytecode::ProgramTable truncated =
            table;
        truncated.programs.pop_back();
        fp::FoldBusComposition forged_attempt = base;
        const fp::BytecodeInterpreterAttachment forged =
            fp::AttachConstraintBytecodeInterpreter(
                forged_attempt, truncated);
        BOOST_CHECK(!forged.valid);
        BOOST_CHECK(
            forged.note.find(
                "bytecode_child_constraint_table") !=
            std::string::npos);
    }
    static_assert(!fp::kCompleteRecursiveFixedPointExecutable);
}

// Fast (no prove): pin hash-kernel instruction/row projection against the
// measured 575-col × 32,768-row narrow multi-child shape. Documents that the
// full 462-program kernel cannot join vertically on ONE node even after
// consuming all rows as free — projected LDE exceeds 2^kRCFriMaxLdeLog2 —
// while PlanNarrowBytecodeHierarchicalAttachV1 closes the same table under
// AssessNarrowNodeFriShape. P2 FS closure is true via the ledger; CompleteFP
// stays false.
BOOST_AUTO_TEST_CASE(
    hash_kernel_narrow_575_bytecode_join_budget_capacity_closed)
{
    rc::constraint_bytecode::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledHashKernelProgramTable(
            rc::RCStage3RelationRole::EpisodeTileTree,
            table, &why),
        why);
    BOOST_REQUIRE_EQUAL(table.programs.size(), 462U);
    const uint64_t instructions =
        fp::CountProgramTableInstructions(table);
    BOOST_REQUIRE_GT(instructions, 0U);
    constexpr uint32_t kNarrowCols = 575;
    constexpr uint32_t kNarrowRows = 32768;
    constexpr uint32_t kQueries = 192;
    const uint64_t rows_needed =
        uint64_t{kQueries} * (instructions + 1U);
    BOOST_REQUIRE_GT(rows_needed, kNarrowRows);
    const uint64_t projected =
        [&]() -> uint64_t {
            uint64_t out = 1;
            const uint64_t min_rows =
                uint64_t{kNarrowRows} +
                (rows_needed - kNarrowRows);
            while (out < min_rows) {
                if (out > (uint64_t{1} << 30)) return 0;
                out <<= 1;
            }
            return out;
        }();
    BOOST_REQUIRE_GT(projected, 0U);
    const nr::NarrowNodeFriShape projected_domain =
        nr::AssessNarrowNodeFriShape(
            rows_needed,
            kNarrowCols +
                (fp::BytecodeBusLayout(kNarrowCols).End() -
                 kNarrowCols));
    BOOST_REQUIRE_EQUAL(
        projected_domain.trace_rows, projected);
    BOOST_CHECK_EQUAL(
        projected_domain.max_algebraic_degree,
        nr::kMeasuredNarrowMaxAlgebraicDegree);
    BOOST_CHECK_EQUAL(
        projected_domain.quotient_len,
        uint64_t{
            nr::kMeasuredNarrowMaxAlgebraicDegree - 1} *
            (projected - 1));
    BOOST_CHECK_GT(projected_domain.n_coeffs, projected);
    const uint64_t projected_lde = projected_domain.n_lde;
    BOOST_CHECK_GT(
        projected_lde, uint64_t{1} << 24);
    const uint32_t bytecode_cols =
        fp::BytecodeBusLayout(kNarrowCols).End() -
        kNarrowCols;
    BOOST_CHECK_LT(kNarrowCols + bytecode_cols, 1024U);
    BOOST_CHECK(
        rc::recursive_parent_air::
            AssessChildFsReplayClosureV1()
                .closed);

    const fp::NarrowBytecodeHierarchicalAttachPlanV1 hier =
        fp::PlanNarrowBytecodeHierarchicalAttachV1(
            table, kQueries);
    BOOST_REQUIRE_MESSAGE(hier.valid, hier.note);
    BOOST_CHECK(!hier.single_node_fits);
    BOOST_CHECK(hier.hierarchical_fits);
    BOOST_CHECK(hier.all_programs_covered);
    BOOST_CHECK_GE(hier.depth, 2U);
    BOOST_CHECK_GE(hier.node_count, 3U);
    BOOST_CHECK_GT(hier.total_leaf_rows, rows_needed);
    for (const auto& node : hier.hierarchy.nodes) {
        BOOST_CHECK(node.shape.representable);
        BOOST_CHECK_LE(node.shape.n_lde, uint32_t{1} << 24);
        BOOST_CHECK_EQUAL(
            node.shape.vcs_columns, 575U);
    }

    BOOST_TEST_MESSAGE(
        "NARROW_575_JOIN instructions=" << instructions
        << " needed=" << rows_needed
        << " projected_rows=" << projected
        << " quotient_len=" << projected_domain.quotient_len
        << " n_coeffs=" << projected_domain.n_coeffs
        << " projected_lde=" << projected_lde
        << " bytecode_cols=" << bytecode_cols
        << " capacity_closed=true"
        << " hier_fits=1 depth=" << hier.depth
        << " nodes=" << hier.node_count
        << " leaf_rows=" << hier.total_leaf_rows
        << " complete_fp=false");
    static_assert(!fp::kCompleteRecursiveFixedPointExecutable);
    static_assert(
        !nr::kNarrowHierarchicalAggregationReady);
}

BOOST_AUTO_TEST_CASE(
    narrow_bytecode_join_report_uses_exact_quotient_domain)
{
    const HonestChild hash_child = BuildHashKernelChild();
    const fp::FoldBusComposition base =
        fp::BuildFoldBusComposition(
            hash_child.cs,
            hash_child.proof,
            hash_child.seed);
    BOOST_REQUIRE_MESSAGE(base.valid, base.note);
    rc::constraint_bytecode::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledHashKernelProgramTable(
            rc::RCStage3RelationRole::EpisodeTileTree,
            table, &why),
        why);
    const fp::NarrowBytecodePerPointJoinBudgetV1 budget =
        fp::AssessNarrowBytecodePerPointJoinBudgetV1(
            base, table);
    BOOST_REQUIRE_MESSAGE(budget.valid, budget.note);
    BOOST_CHECK(
        budget.exact_quotient_degree_accounting);
    BOOST_CHECK_EQUAL(
        budget.projected_max_algebraic_degree,
        nr::kMeasuredNarrowMaxAlgebraicDegree);
    BOOST_CHECK_EQUAL(
        budget.projected_quotient_len,
        uint64_t{
            nr::kMeasuredNarrowMaxAlgebraicDegree - 1} *
            (budget.projected_trace_rows - 1));
    BOOST_CHECK_EQUAL(
        budget.projected_coefficient_rows,
        uint64_t{1} << 22);
    BOOST_CHECK_EQUAL(
        budget.projected_lde,
        uint64_t{1} << 26);
    BOOST_CHECK_GT(
        budget.projected_lde,
        budget.projected_trace_rows *
            rc::kRCFriBlowup);
    BOOST_CHECK(!budget.projected_lde_supported);
    BOOST_CHECK(budget.capacity_closed);
    BOOST_CHECK(
        !budget.single_node_fri_representable);
    static_assert(!fp::kCompleteRecursiveFixedPointExecutable);
}

// g2: actually EXECUTE hierarchical bytecode shard attach — not just plan.
// FRI plan (depth=3, nodes=6) closes under AssessNarrowNodeFriShape. L1
// attach packs programs into free-row shards (pad-after-challenge is
// forbidden on an already-bound fold-bus), AttachConstraintBytecodeInterpreterShard
// closes dual-logup with a local synthesized q, and bus forgeries are
// rejected. L2/L3 nodes are schedule-checked. CompleteFP stays false.
BOOST_AUTO_TEST_CASE(
    hash_kernel_hierarchical_bytecode_shard_attach_executes_l1_with_forgery_rejects)
{
    const HonestChild hash_child = BuildHashKernelChild();
    const fp::FoldBusComposition base =
        fp::BuildFoldBusComposition(
            hash_child.cs, hash_child.proof, hash_child.seed);
    BOOST_REQUIRE_MESSAGE(base.valid, base.note);

    rc::constraint_bytecode::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledHashKernelProgramTable(
            rc::RCStage3RelationRole::EpisodeTileTree,
            table, &why),
        why);
    BOOST_REQUIRE_EQUAL(table.programs.size(), 462U);

    const fp::NarrowBytecodeHierarchicalAttachExecutionV1
        scheduled =
            fp::ExecuteNarrowBytecodeHierarchicalAttachV1(
                base, table, /*attach_l1=*/false);
    BOOST_REQUIRE_MESSAGE(scheduled.plan_valid, scheduled.note);
    BOOST_CHECK_GE(scheduled.l1_count, 2U);
    BOOST_CHECK_GE(scheduled.composed_count, 1U);
    BOOST_CHECK_EQUAL(scheduled.depth, 3U);
    BOOST_CHECK_EQUAL(scheduled.node_count, 6U);
    BOOST_CHECK(scheduled.all_nodes_representable);
    BOOST_CHECK(scheduled.all_composed_scheduled);
    BOOST_CHECK(scheduled.p2_fs_replay_closed);
    BOOST_CHECK(!scheduled.complete_verifier_mirror);
    BOOST_CHECK(!scheduled.all_l1_attached);
    BOOST_TEST_MESSAGE(scheduled.note);

    const fp::NarrowBytecodeHierarchicalAttachExecutionV1
        executed =
            fp::ExecuteNarrowBytecodeHierarchicalAttachV1(
                base, table, /*attach_l1=*/true);
    BOOST_REQUIRE_MESSAGE(executed.valid, executed.note);
    BOOST_CHECK(executed.all_l1_attached);
    BOOST_CHECK(executed.all_l1_forgeries_rejected);
    BOOST_CHECK_EQUAL(executed.l1_attached, executed.l1_count);
    BOOST_CHECK_GE(executed.l1_count, 2U);
    BOOST_CHECK(executed.all_composed_scheduled);
    BOOST_CHECK(executed.p2_fs_replay_closed);
    // complete_verifier_mirror earned below when absolute AIR-mirrored join
    // closes; scheduled path (attach_l1=false) must stay false.
    BOOST_CHECK(!scheduled.complete_verifier_mirror);

    uint32_t free_l1 = 0;
    uint32_t composed_seen = 0;
    for (const auto& node : executed.nodes) {
        if (node.label.rfind("freeL1-", 0) == 0) {
            ++free_l1;
            BOOST_CHECK(node.pad_ok);
            BOOST_CHECK(node.attached);
            BOOST_CHECK(node.dual_logup_terminal);
            BOOST_CHECK(node.quotient_opening_equality);
            BOOST_CHECK(node.forgery_rejected);
            BOOST_CHECK_EQUAL(node.violations, 0U);
            BOOST_CHECK_GT(node.program_count, 0U);
            BOOST_TEST_MESSAGE(
                node.label
                << " programs=" << node.program_count
                << " insn=" << node.instructions
                << " needed=" << node.rows_needed
                << " attached=1 forgery=1");
        } else if (node.level >= 2) {
            ++composed_seen;
            BOOST_CHECK(node.shape_representable);
            BOOST_CHECK_LE(node.n_lde, uint32_t{1} << 24);
            BOOST_CHECK(
                node.note.find("composed_scheduled") !=
                std::string::npos);
        }
    }
    BOOST_CHECK_EQUAL(free_l1, executed.l1_count);
    BOOST_CHECK_EQUAL(composed_seen, executed.composed_count);

    BOOST_REQUIRE(!executed.plan.hierarchy.nodes.empty());
    const auto& fri_l1 = executed.plan.hierarchy.nodes.front();
    BOOST_REQUIRE_EQUAL(fri_l1.level, 1U);
    BOOST_REQUIRE_GE(fri_l1.child_leaf_indices.size(), 1U);
    std::vector<uint32_t> small_leaves = {
        fri_l1.child_leaf_indices.front()};
    rc::constraint_bytecode::ProgramTable shard;
    BOOST_REQUIRE(fp::SliceProgramTableByLeafIndices(
        table, small_leaves, shard, &why));
    auto truncated = shard;
    truncated.programs.pop_back();
    fp::FoldBusComposition forged_bus;
    BOOST_CHECK(!fp::PrepareFoldBusForBytecodeShard(
        base, table, small_leaves, truncated, forged_bus,
        &why));
    BOOST_CHECK(
        why.find("bytecode_hier_shard_prepare_input") !=
            std::string::npos ||
        why.find("bytecode_hier_shard_metadata") !=
            std::string::npos);

    std::vector<uint32_t> oob = small_leaves;
    oob.push_back(static_cast<uint32_t>(table.programs.size()));
    rc::constraint_bytecode::ProgramTable oob_table;
    BOOST_CHECK(!fp::SliceProgramTableByLeafIndices(
        table, oob, oob_table, &why));
    BOOST_CHECK(
        why.find("bytecode_hier_shard_leaf_oob") !=
        std::string::npos);

    // L2 local-q join: relative partition + drop-shard forgery measured on
    // the free-row pack. Absolute Σ local_q == parent opening is reported
    // when parent openings extract; do not require it to flip readiness.
    BOOST_CHECK_EQUAL(
        executed.quotient_join.shard_count, executed.l1_count);
    BOOST_CHECK(executed.quotient_join.covers_full_table);
    BOOST_CHECK(executed.quotient_join.shards_extracted);
    BOOST_CHECK(executed.quotient_join.partition_closed);
    BOOST_CHECK(executed.quotient_join.forgery_rejected);
    BOOST_CHECK_EQUAL(
        executed.quotient_join.programs_covered,
        static_cast<uint32_t>(table.programs.size()));
    BOOST_TEST_MESSAGE(executed.quotient_join.note);
    BOOST_TEST_MESSAGE(executed.quotient_join.air_mirror.note);
    BOOST_TEST_MESSAGE(executed.note);
    // Absolute parent binding + AIR mirror earn runtime
    // complete_verifier_mirror; Ready constexprs stay false.
    BOOST_CHECK(!fp::kNarrowBytecodeShardQuotientJoinReady);
    if (executed.quotient_join.parent_extracted) {
        BOOST_TEST_MESSAGE(
            "parent_q extracted; sum_eq="
            << executed.quotient_join.sum_equals_parent
            << " join_valid=" << executed.quotient_join.valid
            << " air_mirrored="
            << executed.quotient_join.air_mirrored
            << " complete_verifier_mirror="
            << executed.complete_verifier_mirror);
        if (executed.quotient_join.sum_equals_parent) {
            BOOST_REQUIRE_MESSAGE(
                executed.quotient_join.air_mirrored,
                executed.quotient_join.air_mirror.note);
            BOOST_CHECK(executed.complete_verifier_mirror);
            BOOST_CHECK(
                executed.quotient_join.air_mirror
                    .absolute_parent_bound);
            BOOST_CHECK(
                executed.quotient_join.air_mirror
                    .forgery_rejected);
        }
    } else {
        BOOST_TEST_MESSAGE(
            "parent_q not extracted; relative join only");
        BOOST_CHECK(!executed.complete_verifier_mirror);
    }

    static_assert(!fp::kCompleteRecursiveFixedPointExecutable);
    static_assert(!fp::kNarrowBytecodeHierarchicalAttachReady);
    static_assert(
        fp::kNarrowBytecodeHierarchicalAttachExecutable);
    static_assert(fp::kNarrowBytecodeShardQuotientJoinExecutable);
    static_assert(!fp::kNarrowBytecodeShardQuotientJoinReady);
    static_assert(
        !nr::kNarrowHierarchicalAggregationReady);
}

// g2: light absolute/relative local-q join on a 2-shard subset (fits free
// rows; no pad-after-challenge). Measures partition+forgery; absolute
// parent binding only asserted when parent openings extract successfully.
BOOST_AUTO_TEST_CASE(
    hash_kernel_bytecode_shard_local_quotient_join_rejects_drop_forgery)
{
    const HonestChild hash_child = BuildHashKernelChild();
    const fp::FoldBusComposition base =
        fp::BuildFoldBusComposition(
            hash_child.cs, hash_child.proof, hash_child.seed);
    BOOST_REQUIRE_MESSAGE(base.valid, base.note);

    rc::constraint_bytecode::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledHashKernelProgramTable(
            rc::RCStage3RelationRole::EpisodeTileTree,
            table, &why),
        why);
    BOOST_REQUIRE_GE(table.programs.size(), 4U);

    // Two tiny shards of one program each — must fit free rows.
    const std::vector<std::vector<uint32_t>> groups = {
        {0U}, {1U}};
    const fp::NarrowBytecodeShardQuotientJoinV1 join =
        fp::ExecuteNarrowBytecodeShardQuotientJoinV1(
            base, table, groups);
    BOOST_REQUIRE_MESSAGE(join.valid, join.note);
    BOOST_CHECK_EQUAL(join.shard_count, 2U);
    BOOST_CHECK_EQUAL(join.programs_covered, 2U);
    BOOST_CHECK(!join.covers_full_table);
    BOOST_CHECK(join.shards_extracted);
    BOOST_CHECK(join.partition_closed);
    BOOST_CHECK(join.forgery_rejected);
    BOOST_CHECK(!join.sum_equals_parent);
    BOOST_REQUIRE_MESSAGE(
        join.air_mirrored, join.air_mirror.note);
    BOOST_CHECK(join.air_mirror.proved);
    BOOST_CHECK(join.air_mirror.verified);
    BOOST_CHECK(join.air_mirror.forgery_rejected);
    BOOST_CHECK(!join.air_mirror.absolute_parent_bound);
    BOOST_CHECK_EQUAL(join.air_mirror.shard_count, 2U);
    BOOST_CHECK_EQUAL(join.air_mirror.queries, join.queries);

    // Relative identity: Σ shard local_q == union-shard local_q.
    std::vector<uint32_t> union_leaves = {0U, 1U};
    rc::constraint_bytecode::ProgramTable union_table;
    BOOST_REQUIRE(fp::SliceProgramTableByLeafIndices(
        table, union_leaves, union_table, &why));
    fp::FoldBusComposition union_bus;
    BOOST_REQUIRE(fp::PrepareFoldBusForBytecodeShard(
        base, table, union_leaves, union_table, union_bus,
        &why));
    const fp::BytecodeInterpreterAttachment union_att =
        fp::AttachConstraintBytecodeInterpreterShard(
            union_bus, union_table, union_leaves);
    BOOST_REQUIRE_MESSAGE(union_att.valid, union_att.note);
    std::vector<gf::Fp3> union_q;
    BOOST_REQUIRE(fp::ExtractShardLocalQuotientOpenings(
        union_bus, union_q, &why));
    BOOST_REQUIRE_EQUAL(union_q.size(), join.queries);
    BOOST_REQUIRE_EQUAL(
        join.sum_local_q_per_query.size(), join.queries);
    for (uint32_t q = 0; q < join.queries; ++q) {
        BOOST_CHECK_MESSAGE(
            gf::IsZero(gf::Sub(
                join.sum_local_q_per_query[q], union_q[q])),
            "relative sum!=union at query " << q);
    }
    BOOST_TEST_MESSAGE(join.note);
    BOOST_TEST_MESSAGE(join.air_mirror.note);
    BOOST_TEST_MESSAGE(
        "Q_JOIN_AIR_MIRROR shards=2 covered=2/"
        << table.programs.size()
        << " queries=" << join.queries
        << " union_eq=1 forgery=1 mirror=1 abs=0"
        << " verify_us=" << join.air_mirror.verify_micros
        << " complete_fp=false");
    static_assert(!fp::kNarrowBytecodeShardQuotientJoinReady);
    static_assert(fp::kNarrowBytecodeShardQuotientJoinExecutable);
    static_assert(!fp::kCompleteRecursiveFixedPointExecutable);
}

// g2: pure AIR-mirror of absolute Σ shards == parent (synthetic openings;
// no fold-bus). Proves/verifies with forgery reject under ≤900ms-scale.
BOOST_AUTO_TEST_CASE(
    hash_kernel_bytecode_q_join_air_mirror_absolute_synthetic)
{
    constexpr uint32_t kQueries = 8;
    constexpr uint32_t kShards = 3;
    std::vector<std::vector<gf::Fp3>> shards(
        kShards, std::vector<gf::Fp3>(kQueries));
    std::vector<gf::Fp3> parent(kQueries, gf::Fp3::Zero());
    for (uint32_t q = 0; q < kQueries; ++q) {
        for (uint32_t s = 0; s < kShards; ++s) {
            shards[s][q] = gf::Fp3::FromFp(
                gf::Fp{uint64_t{1000 + 17 * q + 3 * s}});
            parent[q] = gf::Add(parent[q], shards[s][q]);
        }
    }
    const fp::NarrowBytecodeShardQuotientJoinAirMirrorV1 mirror =
        fp::AirMirrorNarrowBytecodeShardLocalQuotientsV1(
            parent, shards, /*absolute_parent_bound=*/true);
    BOOST_REQUIRE_MESSAGE(mirror.valid, mirror.note);
    BOOST_CHECK(mirror.proved);
    BOOST_CHECK(mirror.verified);
    BOOST_CHECK(mirror.operands_preprocessed);
    BOOST_CHECK(mirror.forgery_rejected);
    BOOST_CHECK(mirror.compensated_forgery_rejected);
    BOOST_CHECK(mirror.absolute_parent_bound);
    BOOST_CHECK_EQUAL(mirror.queries, kQueries);
    BOOST_CHECK_EQUAL(mirror.shard_count, kShards);
    BOOST_CHECK_LT(mirror.verify_micros, 900000ULL);
    BOOST_TEST_MESSAGE(mirror.note);
    BOOST_TEST_MESSAGE(
        "Q_JOIN_AIR_ABS_SYNTH mirror=1 forgery=1 verify_us="
        << mirror.verify_micros << " complete_fp=false");
    static_assert(!fp::kCompleteRecursiveFixedPointExecutable);
    static_assert(!nr::kNarrowHierarchicalAggregationReady);
}

// g2 chip A: AirQuotientProveRows one free-row L1 shard composition
// (fold-bus + bytecode) with forgery reject. Heavy (≈131k×640 streaming);
// opt-in via BTX_RUN_G2_L1_SHARD_COMPOSITION_AIR=1. Does NOT flip Ready.
BOOST_AUTO_TEST_CASE(
    hash_kernel_one_free_row_l1_shard_composition_air_prove)
{
    const char* run_env =
        std::getenv("BTX_RUN_G2_L1_SHARD_COMPOSITION_AIR");
    if (run_env == nullptr || run_env[0] == '\0' ||
        run_env[0] == '0') {
        BOOST_TEST_MESSAGE(
            "skip: set BTX_RUN_G2_L1_SHARD_COMPOSITION_AIR=1 "
            "for free-row L1 shard composition AirQuotientProveRows");
        return;
    }

    const HonestChild hash_child = BuildHashKernelChild();
    const fp::FoldBusComposition base =
        fp::BuildFoldBusComposition(
            hash_child.cs, hash_child.proof, hash_child.seed);
    BOOST_REQUIRE_MESSAGE(base.valid, base.note);
    BOOST_CHECK_EQUAL(base.combined.n_columns, 575U);
    BOOST_CHECK_EQUAL(base.combined.n_rows, 131072U);

    rc::constraint_bytecode::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledHashKernelProgramTable(
            rc::RCStage3RelationRole::EpisodeTileTree,
            table, &why),
        why);
    BOOST_REQUIRE_EQUAL(table.programs.size(), 462U);

    const fp::NarrowBytecodeShardCompositionAirProveV1 proved =
        fp::ExecuteNarrowBytecodeOneFreeRowShardCompositionAirProveV1(
            base, table);
    BOOST_REQUIRE_MESSAGE(proved.valid, proved.note);
    BOOST_CHECK(proved.attached);
    BOOST_CHECK(proved.proved);
    BOOST_CHECK(proved.verified);
    BOOST_CHECK(proved.forgery_rejected);
    BOOST_CHECK(proved.streaming);
    BOOST_CHECK_EQUAL(proved.n_rows, 131072U);
    BOOST_CHECK_EQUAL(proved.n_columns, 640U);
    BOOST_CHECK_GT(proved.program_count, 0U);
    BOOST_CHECK_GT(proved.prove_micros, 0ULL);
    BOOST_TEST_MESSAGE(proved.note);
    BOOST_TEST_MESSAGE(
        "L1_SHARD_COMPOSITION_AIR rows="
        << proved.n_rows << " cols=" << proved.n_columns
        << " programs=" << proved.program_count
        << " shard=" << proved.shard_index
        << " prove_us=" << proved.prove_micros
        << " verify_us=" << proved.verify_micros
        << " forgery=1 complete_fp=false");

    static_assert(
        fp::kNarrowBytecodeShardCompositionAirProveExecutable);
    static_assert(
        !fp::kNarrowBytecodeShardCompositionAirProveReady);
    static_assert(!fp::kCompleteRecursiveFixedPointExecutable);
    static_assert(!nr::kNarrowHierarchicalAggregationReady);
}

// g2 chip A canary: same AirProve helper on the 575-col fold-bus alone
// (boolean child, no bytecode) — proves streaming composition path + forgery
// reject under a light shape without the hash-kernel free-row pack.
BOOST_AUTO_TEST_CASE(
    boolean_fold_bus_composition_air_prove_rejects_forgery)
{
    const HonestChild child = BuildHonestChild(0xA1);
    const fp::FoldBusComposition joined =
        fp::BuildFoldBusComposition(
            child.cs, child.proof, child.seed);
    BOOST_REQUIRE_MESSAGE(joined.valid, joined.note);
    BOOST_CHECK_EQUAL(joined.combined.n_columns, 575U);
    BOOST_CHECK_EQUAL(joined.combined.n_rows, 8192U);

    const fp::NarrowBytecodeShardCompositionAirProveV1 proved =
        fp::AirProveNarrowBytecodeShardCompositionV1(joined);
    BOOST_REQUIRE_MESSAGE(proved.valid, proved.note);
    BOOST_CHECK(proved.attached);
    BOOST_CHECK(proved.proved);
    BOOST_CHECK(proved.verified);
    BOOST_CHECK(proved.forgery_rejected);
    BOOST_CHECK_EQUAL(proved.n_rows, 8192U);
    BOOST_CHECK_EQUAL(proved.n_columns, 575U);
    BOOST_TEST_MESSAGE(proved.note);
    BOOST_TEST_MESSAGE(
        "FOLD_BUS_COMPOSITION_AIR rows="
        << proved.n_rows << " cols=" << proved.n_columns
        << " prove_us=" << proved.prove_micros
        << " verify_us=" << proved.verify_micros
        << " forgery=1 complete_fp=false");
    static_assert(
        fp::kNarrowBytecodeShardCompositionAirProveExecutable);
    static_assert(
        !fp::kNarrowBytecodeShardCompositionAirProveReady);
    static_assert(!fp::kCompleteRecursiveFixedPointExecutable);
}

// g2 chip B: multi-child L2 FRI consume of ≥2 L1 proofs under FRI shape
// (BuildFoldBusCompositionMulti cryptographic join — NOT host Σ local_q /
// AIR-mirror). Light arity-2 canary on two boolean children. Opt-in via
// BTX_RUN_G2_MULTI_CHILD_L2=1. Does NOT flip Ready / AggregationReady.
BOOST_AUTO_TEST_CASE(
    boolean_arity2_l2_fri_consume_rejects_child_forgery)
{
    const char* run_env =
        std::getenv("BTX_RUN_G2_MULTI_CHILD_L2");
    if (run_env == nullptr || run_env[0] == '\0' ||
        run_env[0] == '0') {
        BOOST_TEST_MESSAGE(
            "skip: set BTX_RUN_G2_MULTI_CHILD_L2=1 for "
            "arity-2 L2 FRI multi-child consume "
            "(BuildFoldBusCompositionMulti + AirProve)");
        return;
    }

    const HonestChild a = BuildHonestChild(0xB1);
    const HonestChild b = BuildHonestChild(0xB2);

    // Shape-only first (prove=false): fold-bus + FRI + forgery.
    const fp::NarrowMultiChildL2FriConsumeV1 shape =
        fp::ExecuteNarrowMultiChildL2FriConsumeV1(
            {a.cs, b.cs}, {a.proof, b.proof},
            {a.seed, b.seed}, /*prove=*/false);
    BOOST_REQUIRE_MESSAGE(shape.valid, shape.note);
    BOOST_CHECK(shape.fold_bus_built);
    BOOST_CHECK(shape.fri_shape_representable);
    BOOST_CHECK(shape.forgery_rejected);
    BOOST_CHECK(!shape.proved);
    BOOST_CHECK_EQUAL(shape.arity, 2U);
    BOOST_CHECK_EQUAL(shape.n_columns, 575U);
    BOOST_CHECK_GE(shape.n_rows, 8192U);
    BOOST_CHECK_LE(shape.n_lde, uint32_t{1} << 24);
    BOOST_TEST_MESSAGE(shape.note);

    // Full cryptographic L2 consume: AirQuotientProve/Verify the joined node.
    const fp::NarrowMultiChildL2FriConsumeV1 consumed =
        fp::ExecuteNarrowMultiChildL2FriConsumeV1(
            {a.cs, b.cs}, {a.proof, b.proof},
            {a.seed, b.seed}, /*prove=*/true);
    BOOST_REQUIRE_MESSAGE(consumed.valid, consumed.note);
    BOOST_CHECK(consumed.fold_bus_built);
    BOOST_CHECK(consumed.fri_shape_representable);
    BOOST_CHECK(consumed.proved);
    BOOST_CHECK(consumed.verified);
    BOOST_CHECK(consumed.forgery_rejected);
    BOOST_CHECK(consumed.parent_proof_tamper_rejected);
    BOOST_CHECK(consumed.parent_proof_retained);
    BOOST_CHECK(consumed.canonical_whole_proof_codec);
    BOOST_CHECK(consumed.parent_reentry_verified);
    BOOST_CHECK(!consumed.parent_fs_seed.IsNull());
    BOOST_CHECK(!consumed.parent_proof_commitment.IsNull());
    BOOST_CHECK(!consumed.parent_statement_commitment.IsNull());
    BOOST_CHECK_EQUAL(
        consumed.parent_constraint_system.n_columns,
        consumed.n_columns);
    BOOST_CHECK(!consumed.parent_proof_bytes.empty());
    BOOST_CHECK_EQUAL(consumed.arity, 2U);
    BOOST_CHECK_EQUAL(consumed.n_columns, 575U);
    BOOST_CHECK_EQUAL(consumed.n_rows, shape.n_rows);
    BOOST_CHECK_GT(consumed.prove_micros, 0ULL);
    BOOST_CHECK_GT(consumed.verify_micros, 0ULL);
    BOOST_CHECK_GT(consumed.serialize_batch_bytes, 0ULL);
    BOOST_CHECK_GE(
        consumed.serialize_root_bytes,
        consumed.serialize_batch_bytes);
    BOOST_CHECK_EQUAL(
        consumed.serialize_root_bytes,
        consumed.parent_proof_bytes.size());
    BOOST_CHECK_LE(
        consumed.serialize_batch_bytes,
        rc::kRCFriMaxProofBytesHard);
    BOOST_CHECK_MESSAGE(
        consumed.verify_within_relay_budget,
        "narrow L2 verify missed 900ms relay budget: us=" +
            std::to_string(consumed.verify_micros));
    BOOST_CHECK(consumed.serialize_within_fri_budget);
    BOOST_TEST_MESSAGE(consumed.note);
    BOOST_TEST_MESSAGE(
        "MULTI_CHILD_L2_FRI arity=" << consumed.arity
        << " rows=" << consumed.n_rows
        << " cols=" << consumed.n_columns
        << " active=" << consumed.active_rows
        << " n_lde=" << consumed.n_lde
        << " prove_us=" << consumed.prove_micros
        << " verify_us=" << consumed.verify_micros
        << " batch_bytes=" << consumed.serialize_batch_bytes
        << " root_bytes=" << consumed.serialize_root_bytes
        << " verify_within_budget="
        << consumed.verify_within_relay_budget
        << " serialize_within_fri="
        << consumed.serialize_within_fri_budget
        << " forgery=1 complete_fp=false");

    // Pin congruence: recorded budget must match this canary's measured
    // verify/serialize. Ready / AggregationReady stay false.
    const auto budget =
        rc::CurrentRCStage3TwoLevelRootVerifyBudgetV1();
    BOOST_CHECK_EQUAL(budget.measured_narrow_l2_vcs_columns, 575U);
    BOOST_CHECK_EQUAL(budget.measured_narrow_l2_arity, 2U);
    BOOST_CHECK(budget.narrow_l2_root_proof_produced);
    BOOST_CHECK(budget.narrow_l2_root_verify_wall_clock_measured);
    BOOST_CHECK(budget.narrow_l2_within_relay_budget);
    BOOST_CHECK(budget.narrow_l2_serialize_within_fri_budget);
    BOOST_CHECK(budget.within_relay_budget);
    BOOST_CHECK_EQUAL(
        budget.measured_narrow_l2_root_verify_micros,
        rc::kRCStage3MeasuredNarrowL2RootVerifyMicros);
    BOOST_CHECK_EQUAL(
        budget.measured_narrow_l2_serialize_batch_bytes,
        rc::kRCStage3MeasuredNarrowL2SerializeBatchBytes);
    // Canary remasure must stay within a factor of the pinned verify
    // (machine noise); pin itself is the ledger authority.
    BOOST_CHECK_LE(consumed.verify_micros, 900000ULL);
    BOOST_CHECK_LE(
        consumed.serialize_batch_bytes,
        rc::kRCFriMaxProofBytesHard);
    BOOST_TEST_MESSAGE(
        "BUDGET_PIN within_relay_budget="
        << budget.within_relay_budget
        << " narrow_l2_within="
        << budget.narrow_l2_within_relay_budget
        << " narrow_l2_serialize_within_fri="
        << budget.narrow_l2_serialize_within_fri_budget
        << " pinned_verify_us="
        << budget.measured_narrow_l2_root_verify_micros
        << " pinned_batch_bytes="
        << budget.measured_narrow_l2_serialize_batch_bytes
        << " note=" << budget.note);

    static_assert(fp::kNarrowMultiChildL2FriConsumeExecutable);
    static_assert(!fp::kNarrowMultiChildL2FriConsumeReady);
    static_assert(!fp::kCompleteRecursiveFixedPointExecutable);
    static_assert(!nr::kNarrowHierarchicalAggregationReady);
    static_assert(!rc::kRCStage3RecursiveAggregationReady);
}

// g2 fixed-point foundation: two independently produced narrow parents are
// retained as proof-owned receipts and re-entered as the REAL children of a
// next-level narrow parent.  This is the missing data-flow behind the former
// hierarchical boolean stand-in.  The canary is opt-in because it produces
// three FRI proofs; no readiness flag is changed.
BOOST_AUTO_TEST_CASE(
    retained_narrow_receipts_reenter_a_real_next_level_parent)
{
    const char* run_env =
        std::getenv("BTX_RUN_G2_RETAINED_RECEIPT_FIXEDPOINT");
    if (run_env == nullptr || run_env[0] == '\0' ||
        run_env[0] == '0') {
        BOOST_TEST_MESSAGE(
            "skip: set BTX_RUN_G2_RETAINED_RECEIPT_FIXEDPOINT=1 "
            "for retained L1 receipts -> real L2 parent");
        return;
    }

    const HonestChild a = BuildHonestChild(0xD1);
    const HonestChild b = BuildHonestChild(0xD2);
    const HonestChild c = BuildHonestChild(0xD3);
    const HonestChild d = BuildHonestChild(0xD4);
    const uint256 left_node = Seed(0xE1);
    const uint256 right_node = Seed(0xE2);
    const uint256 root_node = Seed(0xE3);
    const uint256 left_program = Seed(0xA1);
    const uint256 right_program = Seed(0xA2);
    const uint256 root_program = Seed(0xA3);

    const fp::NarrowMultiChildL2FriConsumeV1 left =
        fp::ExecuteNarrowMultiChildL2FriConsumeV1(
            {a.cs, b.cs}, {a.proof, b.proof},
            {a.seed, b.seed}, /*prove=*/true,
            /*parent_context_binding=*/Seed(0xF1));
    BOOST_REQUIRE_MESSAGE(left.valid, left.note);
    const fp::NarrowMultiChildL2FriConsumeV1 right =
        fp::ExecuteNarrowMultiChildL2FriConsumeV1(
            {c.cs, d.cs}, {c.proof, d.proof},
            {c.seed, d.seed}, /*prove=*/true,
            /*parent_context_binding=*/Seed(0xF2));
    BOOST_REQUIRE_MESSAGE(right.valid, right.note);

    const fp::NarrowRecursiveProofReceiptV1 left_receipt =
        fp::RetainNarrowRecursiveProofReceiptV1(
            left, left_node, left_program);
    const fp::NarrowRecursiveProofReceiptV1 right_receipt =
        fp::RetainNarrowRecursiveProofReceiptV1(
            right, right_node, right_program);
    BOOST_REQUIRE_MESSAGE(
        left_receipt.valid, left_receipt.note);
    BOOST_REQUIRE_MESSAGE(
        right_receipt.valid, right_receipt.note);
    BOOST_CHECK(
        left_receipt.receipt_commitment !=
        right_receipt.receipt_commitment);

    std::string why;
    BOOST_CHECK(fp::ValidateNarrowRecursiveProofReceiptV1(
        left_receipt, left.parent_constraint_system,
        left_node, left_program, &why));
    BOOST_CHECK(fp::ValidateNarrowRecursiveProofReceiptV1(
        right_receipt, right.parent_constraint_system,
        right_node, right_program, &why));
    BOOST_CHECK(!fp::ValidateNarrowRecursiveProofReceiptV1(
        left_receipt, left.parent_constraint_system,
        right_node, left_program, &why));
    BOOST_CHECK(!fp::ValidateNarrowRecursiveProofReceiptV1(
        left_receipt, left.parent_constraint_system,
        left_node, right_program, &why));

    // A prover cannot make its retained callback-bearing AIR authoritative.
    // Even an identically described AIR with altered semantics is rejected by
    // native proof verification against the verifier's expected callbacks.
    auto wrong_expected_cs = left.parent_constraint_system;
    BOOST_REQUIRE(!wrong_expected_cs.constraints.empty());
    wrong_expected_cs.constraints[0].eval =
        [](const std::vector<gf::Fp3>&,
           const std::vector<gf::Fp3>&) {
            return gf::Fp3::One();
        };
    BOOST_CHECK(!fp::ValidateNarrowRecursiveProofReceiptV1(
        left_receipt, wrong_expected_cs,
        left_node, left_program, &why));

    // Canonical-byte tamper is rejected before re-entry.
    auto byte_tamper = left_receipt;
    BOOST_REQUIRE(!byte_tamper.proof_bytes.empty());
    byte_tamper.proof_bytes.back() ^= 0x01U;
    BOOST_CHECK(!fp::ValidateNarrowRecursiveProofReceiptV1(
        byte_tamper, left.parent_constraint_system,
        left_node, left_program, &why));

    // Proof-level tamper is checked by the unmodified AirQuotient verifier.
    auto proof_tamper = left_receipt;
    BOOST_REQUIRE(!proof_tamper.proof.batch.queries.empty());
    BOOST_REQUIRE(
        !proof_tamper.proof.batch.queries[0].row.values.empty());
    proof_tamper.proof.batch.queries[0].row.values[0] =
        gf::Add(
            proof_tamper.proof.batch.queries[0].row.values[0],
            gf::Fp3::One());
    BOOST_CHECK(!fp::ValidateNarrowRecursiveProofReceiptV1(
        proof_tamper, left.parent_constraint_system,
        left_node, left_program, &why));

    // Duplicate/replayed child receipts are never accepted as two slots.
    const fp::NarrowRetainedReceiptParentV1 duplicate =
        fp::ExecuteNarrowRetainedReceiptParentV1(
            {left_receipt, left_receipt},
            {left.parent_constraint_system,
             left.parent_constraint_system},
            {left_node, left_node},
            {left_program, left_program},
            root_node, root_program,
            /*prove=*/false);
    BOOST_CHECK(!duplicate.valid);
    BOOST_CHECK(duplicate.duplicate_child_rejected);

    const fp::NarrowRetainedReceiptParentV1 wrong_topology =
        fp::ExecuteNarrowRetainedReceiptParentV1(
            {left_receipt, right_receipt},
            {left.parent_constraint_system,
             right.parent_constraint_system},
            {right_node, left_node},
            {left_program, right_program},
            root_node, root_program,
            /*prove=*/false);
    BOOST_CHECK(!wrong_topology.valid);
    BOOST_CHECK(
        wrong_topology.note.find("narrow_receipt_node_binding") !=
        std::string::npos);

    // Ordered receipt commitments are in the parent's transcript context:
    // swapping slots changes the context even in the shape-only preflight.
    const uint256 forward_context =
        fp::ComputeNarrowRetainedParentContextV1(
            {left_receipt, right_receipt},
            root_node, root_program);
    const uint256 reverse_context =
        fp::ComputeNarrowRetainedParentContextV1(
            {right_receipt, left_receipt},
            root_node, root_program);
    BOOST_CHECK(!forward_context.IsNull());
    BOOST_CHECK(!reverse_context.IsNull());
    BOOST_CHECK(
        forward_context != reverse_context);

    // The actual fixed-point step: retained parent proofs become real children
    // and the resulting root proof is itself retained/re-enterable.
    const fp::NarrowRetainedReceiptParentV1 root =
        fp::ExecuteNarrowRetainedReceiptParentV1(
            {left_receipt, right_receipt},
            {left.parent_constraint_system,
             right.parent_constraint_system},
            {left_node, right_node},
            {left_program, right_program},
            root_node, root_program,
            /*prove=*/true);
    BOOST_REQUIRE_MESSAGE(
        root.cryptographically_valid, root.note);
    BOOST_CHECK(root.all_children_validated);
    BOOST_CHECK(root.ordered_child_context_bound);
    BOOST_CHECK(root.child_tamper_rejected);
    BOOST_CHECK(root.consumed.parent_reentry_verified);
    BOOST_CHECK(root.consumed.parent_proof_tamper_rejected);
    BOOST_CHECK(root.consumed.serialize_within_fri_budget);
    BOOST_CHECK(root.receipt.valid);
    BOOST_CHECK_EQUAL(
        root.valid, root.production_budget_met);
    BOOST_CHECK_EQUAL(
        root.production_budget_met,
        root.consumed.verify_within_relay_budget &&
            root.consumed.serialize_within_fri_budget);
    BOOST_CHECK(fp::ValidateNarrowRecursiveProofReceiptV1(
        root.receipt, root.consumed.parent_constraint_system,
        root_node, root_program, &why));
    BOOST_CHECK_EQUAL(root.receipt.n_columns, 575U);
    BOOST_CHECK_EQUAL(root.receipt.n_columns,
                      left_receipt.n_columns);
    BOOST_CHECK_LE(root.consumed.serialize_root_bytes,
                   rc::kRCFriMaxProofBytesHard);
    BOOST_TEST_MESSAGE(
        "RETAINED_RECEIPT_FIXEDPOINT L1_cols="
        << left_receipt.n_columns
        << " root_cols=" << root.receipt.n_columns
        << " root_rows=" << root.receipt.n_rows
        << " kinds_everywhere="
        << root.consumed.everywhere_constraints
        << " kinds_transition="
        << root.consumed.transition_constraints
        << " kinds_first="
        << root.consumed.first_row_constraints
        << " kinds_last="
        << root.consumed.last_row_constraints
        << " root_verify_us=" << root.consumed.verify_micros
        << " standalone_batch_verify_us="
        << root.consumed.standalone_batch_verify_micros
        << " root_bytes=" << root.consumed.serialize_root_bytes
        << " within_relay="
        << root.consumed.verify_within_relay_budget
        << " exact_replay=0 complete_fp=false");

    static_assert(fp::kNarrowRetainedReceiptRecursionExecutable);
    static_assert(!fp::kNarrowMultiChildL2FriConsumeReady);
    static_assert(!fp::kCompleteRecursiveFixedPointExecutable);
    static_assert(!nr::kNarrowHierarchicalAggregationReady);
    static_assert(!rc::kRCStage3RecursiveAggregationReady);
}

BOOST_AUTO_TEST_CASE(
    normalized_batch_codec_is_safe_v13_version_separated)
{
    std::vector<std::vector<gf::Fp3>> columns(
        2, std::vector<gf::Fp3>(8, gf::Fp3::Zero()));
    for (uint32_t column = 0; column < columns.size();
         ++column) {
        for (uint32_t row = 0; row < columns[column].size();
             ++row) {
            columns[column][row] = gf::Fp3{
                gf::FromU64(1 + 19 * column + 7 * row),
                gf::FromU64(3 + 11 * column + 5 * row),
                gf::FromU64(9 + 13 * column + 17 * row)};
        }
    }
    const uint256 seed = Seed(0xB7);
    const auto proved =
        rc::Fri3AlgSafeQ192K2V13BatchCommit(
            columns, seed, 7);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE_EQUAL(
        proved.proof.version,
        rc::kRCFri3AlgSafeQ192K2ProofVersionV13);

    std::string why;
    fp::NormalizedAlgAirBatchCodecMapV1 map;
    BOOST_REQUIRE_MESSAGE(
        fp::BuildNormalizedAlgAirBatchCodecMapV1(
            proved.proof, map, &why),
        why);
    BOOST_CHECK(map.valid);
    BOOST_CHECK(map.canonical_roundtrip);
    BOOST_CHECK(map.no_trailing_bytes);

    std::vector<unsigned char> encoded;
    const size_t encoded_size =
        rc::SerializeFri3AlgBatchProof(
            proved.proof, encoded);
    BOOST_REQUIRE_EQUAL(encoded_size, encoded.size());
    BOOST_CHECK(
        fp::ValidateNormalizedAlgAirBatchCodecBytesV1(
            proved.proof, encoded, &why));

    // Dispatch is selected by the statement's exact proof version.  Neither
    // relabelling the statement as V10 nor relabelling the bytes is accepted.
    auto v10_statement = proved.proof;
    v10_statement.version =
        rc::kRCFri3AlgP2Q192K2ProofVersionV10;
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirBatchCodecBytesV1(
            v10_statement, encoded, &why));
    auto v10_bytes = encoded;
    BOOST_REQUIRE_GE(v10_bytes.size(), sizeof(uint32_t));
    v10_bytes[0] =
        static_cast<unsigned char>(
            rc::kRCFri3AlgP2Q192K2ProofVersionV10);
    v10_bytes[1] = 0;
    v10_bytes[2] = 0;
    v10_bytes[3] = 0;
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirBatchCodecBytesV1(
            proved.proof, v10_bytes, &why));
}

BOOST_AUTO_TEST_CASE(
    narrow_root_constraint_kind_inventory_is_exact)
{
    const char* run_env =
        std::getenv("BTX_RUN_G2_CONSTRAINT_KIND_INVENTORY");
    if (run_env == nullptr || run_env[0] == '\0' ||
        run_env[0] == '0') {
        BOOST_TEST_MESSAGE(
            "skip: set BTX_RUN_G2_CONSTRAINT_KIND_INVENTORY=1 "
            "for the real W=575 verifier constraint inventory");
        return;
    }
    const HonestChild a = BuildHonestChild(0xC1);
    const HonestChild b = BuildHonestChild(0xC2);
    const auto shape =
        fp::ExecuteNarrowMultiChildL2FriConsumeV1(
            {a.cs, b.cs}, {a.proof, b.proof},
            {a.seed, b.seed}, /*prove=*/false);
    BOOST_REQUIRE_MESSAGE(shape.valid, shape.note);
    BOOST_CHECK_EQUAL(shape.n_columns, 575U);
    BOOST_CHECK_EQUAL(
        shape.n_constraints,
        shape.everywhere_constraints +
            shape.transition_constraints +
            shape.first_row_constraints +
            shape.last_row_constraints);
    BOOST_TEST_MESSAGE(
        "G2_CONSTRAINT_KINDS columns=" << shape.n_columns
        << " total=" << shape.n_constraints
        << " everywhere=" << shape.everywhere_constraints
        << " transition=" << shape.transition_constraints
        << " first=" << shape.first_row_constraints
        << " last=" << shape.last_row_constraints);
}

// g2 chip B wire: hierarchical composed nodes call
// ExecuteNarrowMultiChildL2FriConsumeV1 (shape-only prove=false stand-in
// boolean children). Replaces crypto_join_pending. Opt-in via
// BTX_RUN_G2_HIER_L2_WIRE=1. Does NOT flip Ready / AggregationReady.
BOOST_AUTO_TEST_CASE(
    hierarchical_composed_nodes_wire_l2_fri_consume_shape_only)
{
    const char* run_env =
        std::getenv("BTX_RUN_G2_HIER_L2_WIRE");
    if (run_env == nullptr || run_env[0] == '\0' ||
        run_env[0] == '0') {
        BOOST_TEST_MESSAGE(
            "skip: set BTX_RUN_G2_HIER_L2_WIRE=1 for "
            "hierarchical composed-node L2 FRI consume wire "
            "(shape-only prove=false)");
        return;
    }

    const HonestChild hash_child = BuildHashKernelChild();
    const fp::FoldBusComposition base =
        fp::BuildFoldBusComposition(
            hash_child.cs, hash_child.proof, hash_child.seed);
    BOOST_REQUIRE_MESSAGE(base.valid, base.note);

    rc::constraint_bytecode::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledHashKernelProgramTable(
            rc::RCStage3RelationRole::EpisodeTileTree,
            table, &why),
        why);
    BOOST_REQUIRE_EQUAL(table.programs.size(), 462U);

    // attach_l1=false keeps this light; wire_l2 + prove=false exercises
    // the composed-node call path without AirQuotientProve of the L2 node.
    const fp::NarrowBytecodeHierarchicalAttachExecutionV1 wired =
        fp::ExecuteNarrowBytecodeHierarchicalAttachV1(
            base, table, /*attach_l1=*/false,
            /*wire_l2_fri_consume=*/true, /*l2_prove=*/false);
    BOOST_REQUIRE_MESSAGE(wired.plan_valid, wired.note);
    BOOST_CHECK(wired.all_composed_scheduled);
    BOOST_CHECK_GE(wired.composed_count, 1U);
    BOOST_REQUIRE_MESSAGE(
        wired.all_composed_l2_wired, wired.note);
    BOOST_CHECK_GE(wired.composed_l2_wired, 1U);
    BOOST_CHECK(!wired.complete_verifier_mirror);
    BOOST_TEST_MESSAGE(wired.note);

    uint32_t wired_nodes = 0;
    uint32_t pending_nodes = 0;
    for (const auto& node : wired.nodes) {
        if (node.level < 2) continue;
        if (node.child_node_count >= 2U) {
            ++wired_nodes;
            BOOST_CHECK(node.l2_fri_consume_invoked);
            BOOST_CHECK(node.l2_fri_consume_valid);
            BOOST_CHECK_EQUAL(
                node.l2_fri_consume_arity, node.child_node_count);
            BOOST_CHECK(node.forgery_rejected);
            BOOST_CHECK(
                node.note.find("crypto_join_wired") !=
                std::string::npos);
            BOOST_CHECK(
                node.note.find("crypto_join_pending") ==
                std::string::npos);
            BOOST_TEST_MESSAGE(
                node.label
                << " arity=" << node.l2_fri_consume_arity
                << " wired=1 valid=1 note=" << node.note);
        } else {
            BOOST_CHECK(!node.l2_fri_consume_invoked);
            BOOST_CHECK(
                node.note.find("crypto_join_arity_lt2") !=
                    std::string::npos ||
                node.note.find("composed_scheduled") !=
                    std::string::npos);
        }
        if (node.note.find("crypto_join_pending") !=
            std::string::npos) {
            ++pending_nodes;
        }
    }
    BOOST_CHECK_EQUAL(wired_nodes, wired.composed_l2_wired);
    BOOST_CHECK_EQUAL(pending_nodes, 0U);
    BOOST_TEST_MESSAGE(
        "HIER_L2_WIRE composed=" << wired.composed_count
        << " wired=" << wired.composed_l2_wired
        << " arity_lt2=" << wired.composed_l2_arity_lt2
        << " complete_fp=false");

    static_assert(fp::kNarrowMultiChildL2FriConsumeExecutable);
    static_assert(!fp::kNarrowMultiChildL2FriConsumeReady);
    static_assert(!fp::kNarrowBytecodeHierarchicalAttachReady);
    static_assert(!fp::kCompleteRecursiveFixedPointExecutable);
    static_assert(!nr::kNarrowHierarchicalAggregationReady);
}

BOOST_AUTO_TEST_SUITE_END()
