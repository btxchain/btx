// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace ar = matmul::v4::rc::air_recurse;
namespace gf = matmul::v4::rc::gkr_field;
namespace col = matmul::v4::rc::stage3_ctl_col;
namespace d2col = matmul::v4::rc::stage3_ctl_degree2_col;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_ctl_tests, BasicTestingSetup)

namespace {

using Fp3 = gf::Fp3;

uint256 Filled(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

rc::RCStage3CtlSchedule Schedule(int8_t multiplicity)
{
    return {{{7, 0, 9, multiplicity},
             {7, 0, 10, multiplicity},
             {7, 1, 9, multiplicity}}};
}

rc::RCStage3CtlParticipantSpec Participant(
    rc::RCStage3RelationRole role, const rc::RCStage3CtlSchedule& schedule)
{
    uint64_t sends = 0;
    uint64_t receives = 0;
    for (const auto& event : schedule.events) {
        sends += event.multiplicity == 1 ? 1 : 0;
        receives += event.multiplicity == -1 ? 1 : 0;
    }
    return {role, schedule.events.size(), sends, receives,
            rc::CommitRCStage3CtlSchedule(schedule)};
}

struct BusFixture {
    rc::RCStage3CtlSchedule send_schedule{Schedule(1)};
    rc::RCStage3CtlSchedule receive_schedule{Schedule(-1)};
    rc::RCStage3CtlManifest manifest;
    std::vector<rc::RCStage3CtlChildPin> pins;
    rc::RCStage3CtlChallenges challenges;
    std::vector<Fp3> values{{11, 1, 2}, {22, 3, 4}, {33, 5, 6}};
    rc::RCStage3CtlWitness send_witness;
    rc::RCStage3CtlWitness receive_witness;

    BusFixture()
    {
        manifest.bus_id = 42;
        manifest.transcript_seed = Filled(0x10);
        manifest.participants = {
            Participant(rc::RCStage3RelationRole::CoupledBank, send_schedule),
            Participant(rc::RCStage3RelationRole::CoupledGemm, receive_schedule),
        };
        pins.resize(2);
        for (size_t i = 0; i < pins.size(); ++i) {
            const auto& expected = manifest.participants[i];
            auto& pin = pins[i];
            pin.role = expected.role;
            pin.bus_id = manifest.bus_id;
            pin.event_count = expected.event_count;
            pin.send_count = expected.send_count;
            pin.receive_count = expected.receive_count;
            pin.schedule_commitment = expected.schedule_commitment;
            pin.trace_commitment = Filled(static_cast<unsigned char>(0x20 + i));
        }
        BOOST_REQUIRE(
            rc::DeriveRCStage3CtlChallenges(manifest, pins, challenges));
        send_witness =
            rc::BuildRCStage3CtlWitness(send_schedule, values, challenges);
        receive_witness =
            rc::BuildRCStage3CtlWitness(receive_schedule, values, challenges);
        BOOST_REQUIRE(send_witness.ok);
        BOOST_REQUIRE(receive_witness.ok);
        const uint256 challenge_commitment =
            rc::CommitRCStage3CtlChallenges(challenges);
        for (size_t i = 0; i < pins.size(); ++i) {
            pins[i].auxiliary_commitment =
                Filled(static_cast<unsigned char>(0x30 + i));
            pins[i].challenge_commitment = challenge_commitment;
        }
        pins[0].terminal = send_witness.terminal;
        pins[1].terminal = receive_witness.terminal;
    }
};

struct ExecutableBusFixture {
    rc::RCStage3CtlSchedule send_schedule{Schedule(1)};
    rc::RCStage3CtlSchedule receive_schedule{Schedule(-1)};
    std::vector<Fp3> values{{11, 1, 2}, {22, 3, 4}, {33, 5, 6}};
    rc::RCStage3CtlManifest manifest;
    std::vector<rc::RCStage3CtlChildPin> pins;
    rc::RCStage3CtlChallenges challenges;
    std::vector<rc::RCStage3CtlAirProof> proofs;

    ExecutableBusFixture()
    {
        manifest.bus_id = 77;
        manifest.transcript_seed = Filled(0x71);
        manifest.participants = {
            Participant(rc::RCStage3RelationRole::CoupledBank, send_schedule),
            Participant(rc::RCStage3RelationRole::CoupledGemm, receive_schedule),
        };
        const std::vector<rc::RCStage3CtlSchedule> schedules{
            send_schedule, receive_schedule};
        pins.resize(2);
        for (size_t i = 0; i < pins.size(); ++i) {
            const auto& expected = manifest.participants[i];
            auto& pin = pins[i];
            pin.role = expected.role;
            pin.bus_id = manifest.bus_id;
            pin.event_count = expected.event_count;
            pin.send_count = expected.send_count;
            pin.receive_count = expected.receive_count;
            pin.schedule_commitment = expected.schedule_commitment;
            pin.trace_commitment =
                rc::ComputeRCStage3CtlPrechallengeTraceCommitment(
                    schedules[i], values);
            BOOST_REQUIRE(!pin.trace_commitment.IsNull());
        }
        BOOST_REQUIRE(
            rc::DeriveRCStage3CtlChallenges(manifest, pins, challenges));
        const uint256 challenge_commitment =
            rc::CommitRCStage3CtlChallenges(challenges);
        proofs.resize(2);
        for (size_t i = 0; i < pins.size(); ++i) {
            const rc::RCStage3CtlWitness witness =
                rc::BuildRCStage3CtlWitness(
                    schedules[i], values, challenges);
            BOOST_REQUIRE(witness.ok);
            pins[i].terminal = witness.terminal;
            pins[i].challenge_commitment = challenge_commitment;
            const uint256 seed =
                rc::ComputeRCStage3CtlAirSeed(manifest, pins[i]);
            BOOST_REQUIRE(!seed.IsNull());
            const auto cs = rc::BuildRCStage3CtlConstraintSystem(
                {schedules[i], challenges, witness.terminal});
            const auto result =
                rc::air_quotient::AirQuotientProve<Fp3>(
                    cs, witness.columns, seed);
            BOOST_REQUIRE_MESSAGE(result.ok, result.note);
            proofs[i] = result.proof;
            pins[i].auxiliary_commitment =
                rc::ComputeRCStage3CtlAuxiliaryCommitment(proofs[i]);
            BOOST_REQUIRE(!pins[i].auxiliary_commitment.IsNull());
        }
    }
};

uint32_t Violations(const rc::air_quotient::AirConstraintSystem<Fp3>& cs,
                    const std::vector<std::vector<Fp3>>& columns)
{
    return ar::CountWitnessViolationsOnH(cs, columns);
}

rc::RCStage3CtlRelationExportPin RelationExport(
    const rc::RCStage3CtlChildPin& child,
    const rc::RCStage3CtlAirProof& proof,
    const uint256& relation_commitment)
{
    rc::RCStage3CtlRelationExportPin out;
    out.role = child.role;
    out.bus_id = child.bus_id;
    out.event_count = child.event_count;
    out.relation_commitment = relation_commitment;
    out.schedule_commitment = child.schedule_commitment;
    out.n_rows = proof.batch.column_len[col::NAMESPACE];
    out.n_coeffs = proof.batch.n_coeffs;
    for (uint32_t column = col::NAMESPACE;
         column <= col::MULTIPLICITY; ++column) {
        out.prechallenge_column_roots[column] =
            proof.batch.columns[column].root;
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(tuple_compression_binds_every_coordinate)
{
    const rc::RCStage3CtlEvent event{5, 6, 7, 1};
    const Fp3 value{8, 9, 10};
    const Fp3 gamma{11, 12, 13};
    const Fp3 base = rc::CompressRCStage3CtlTuple(event, value, gamma);
    auto changed = event;
    ++changed.namespace_id;
    BOOST_CHECK(!gf::Eq(base,
                        rc::CompressRCStage3CtlTuple(changed, value, gamma)));
    changed = event;
    ++changed.stage;
    BOOST_CHECK(!gf::Eq(base,
                        rc::CompressRCStage3CtlTuple(changed, value, gamma)));
    changed = event;
    ++changed.address;
    BOOST_CHECK(!gf::Eq(base,
                        rc::CompressRCStage3CtlTuple(changed, value, gamma)));
    BOOST_CHECK(!gf::Eq(
        base, rc::CompressRCStage3CtlTuple(
                  event, gf::Add(value, Fp3::One()), gamma)));

    // One compression challenge can collide for unequal tuples. Construct
    // such a collision explicitly, then show the independently derived
    // second compression separates it.
    BusFixture fixture;
    BOOST_CHECK(!gf::Eq(fixture.challenges.gamma1,
                        fixture.challenges.gamma2));
    const rc::RCStage3CtlEvent first{1, 0, 0, 1};
    const rc::RCStage3CtlEvent second{2, 0, 0, -1};
    const Fp3 gamma1_cubed = gf::Mul(
        fixture.challenges.gamma1,
        gf::Mul(fixture.challenges.gamma1,
                fixture.challenges.gamma1));
    const Fp3 adversarial_value =
        gf::Neg(gf::Inv(gamma1_cubed));
    const Fp3 first_gamma1 = rc::CompressRCStage3CtlTuple(
        first, Fp3::Zero(), fixture.challenges.gamma1);
    const Fp3 second_gamma1 = rc::CompressRCStage3CtlTuple(
        second, adversarial_value, fixture.challenges.gamma1);
    BOOST_REQUIRE(gf::Eq(first_gamma1, second_gamma1));
    BOOST_CHECK(!gf::Eq(
        rc::CompressRCStage3CtlTuple(
            first, Fp3::Zero(), fixture.challenges.gamma2),
        rc::CompressRCStage3CtlTuple(
            second, adversarial_value, fixture.challenges.gamma2)));
}

BOOST_AUTO_TEST_CASE(challenge_sampler_is_bounded_unbiased_rejection_v3)
{
    BOOST_CHECK_EQUAL(rc::kRCStage3CtlVersion, 3U);
    BOOST_CHECK(rc::kRCStage3CtlUniformChallengeSampling);
    BOOST_CHECK_EQUAL(rc::kRCStage3CtlChallengeBlockCount, 2U);
    BOOST_CHECK_EQUAL(rc::kRCStage3CtlChallengeWordsPerBlock, 4U);
    BOOST_CHECK(
        rc::RCStage3CtlChallengeWordIsAccepted(gf::kP - 1));
    BOOST_CHECK(
        !rc::RCStage3CtlChallengeWordIsAccepted(gf::kP));
    BOOST_CHECK(
        !rc::RCStage3CtlChallengeWordIsAccepted(
            std::numeric_limits<uint64_t>::max()));

    BusFixture fixture;
    rc::RCStage3CtlChallenges repeated;
    BOOST_REQUIRE(rc::DeriveRCStage3CtlChallenges(
        fixture.manifest, fixture.pins, repeated));
    BOOST_CHECK(repeated == fixture.challenges);
    for (const auto& challenge :
         {repeated.gamma1, repeated.gamma2,
          repeated.alpha1, repeated.alpha2}) {
        BOOST_CHECK_LT(challenge.c0, gf::kP);
        BOOST_CHECK_LT(challenge.c1, gf::kP);
        BOOST_CHECK_LT(challenge.c2, gf::kP);
    }
}

BOOST_AUTO_TEST_CASE(air_accepts_honest_accumulator_and_rejects_mutations)
{
    BusFixture fixture;
    const rc::RCStage3CtlAirSpec spec{
        fixture.send_schedule, fixture.challenges,
        fixture.send_witness.terminal};
    const auto cs = rc::BuildRCStage3CtlConstraintSystem(spec);
    BOOST_REQUIRE_EQUAL(cs.n_columns, col::NUM_COLUMNS);
    BOOST_CHECK_EQUAL(Violations(cs, fixture.send_witness.columns), 0U);

    auto bad_value = fixture.send_witness.columns;
    bad_value[col::VALUE][1] =
        gf::Add(bad_value[col::VALUE][1], Fp3::One());
    BOOST_CHECK(Violations(cs, bad_value) > 0);

    auto bad_inverse = fixture.send_witness.columns;
    bad_inverse[col::INVERSE2][0] =
        gf::Add(bad_inverse[col::INVERSE2][0], Fp3::One());
    BOOST_CHECK(Violations(cs, bad_inverse) > 0);

    auto bad_running = fixture.send_witness.columns;
    bad_running[col::RUNNING1][2] =
        gf::Add(bad_running[col::RUNNING1][2], Fp3::One());
    BOOST_CHECK(Violations(cs, bad_running) > 0);
}

BOOST_AUTO_TEST_CASE(
    degree2_exact_ctl_keeps_n_coeffs_equal_to_trace_rows)
{
    BusFixture fixture;
    rc::RCStage3CtlSchedule schedule{{
        {0x44325431U, 3, 100, 1},
        {0x44325431U, 3, 101, 1},
        {0x44325431U, 3, 102, 1},
        {0x44325431U, 3, 103, 1},
    }};
    const std::vector<Fp3> values{
        gf::FromU64_3(0),
        gf::FromU64_3(127),
        gf::FromU64_3(128),
        gf::FromU64_3(255),
    };
    const auto witness =
        rc::BuildRCStage3CtlDegree2Witness(
            schedule, values,
            fixture.challenges);
    BOOST_REQUIRE_MESSAGE(
        witness.ok, witness.note);
    const auto cs =
        rc::BuildRCStage3CtlDegree2ConstraintSystem(
            {rc::kRCStage3CtlDegree2Version,
             schedule, fixture.challenges,
             witness.terminal});
    BOOST_REQUIRE_EQUAL(cs.n_rows, 4U);
    BOOST_REQUIRE_EQUAL(
        cs.n_columns,
        d2col::NUM_COLUMNS);
    BOOST_CHECK_LE(
        cs.QuotientLen(), cs.n_rows);
    BOOST_CHECK_EQUAL(
        rc::FriNextPow2(std::max(
            cs.n_rows, cs.QuotientLen())),
        cs.n_rows);
    BOOST_CHECK_EQUAL(
        Violations(cs, witness.columns), 0U);

    const auto proved =
        rc::air_quotient::AirQuotientProve<Fp3>(
            cs, witness.columns,
            Filled(0xd2));
    BOOST_REQUIRE_MESSAGE(
        proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_CHECK_EQUAL(
        proved.proof.batch.n_coeffs,
        cs.n_rows);

    auto bad_term = witness.columns;
    bad_term[d2col::TERM1][1] =
        gf::Add(
            bad_term[d2col::TERM1][1],
            Fp3::One());
    BOOST_CHECK(
        Violations(cs, bad_term) > 0);

    auto bad_inverse = witness.columns;
    bad_inverse[d2col::INVERSE2][2] =
        gf::Add(
            bad_inverse[d2col::INVERSE2][2],
            Fp3::One());
    BOOST_CHECK(
        Violations(cs, bad_inverse) > 0);

    auto bad_running = witness.columns;
    bad_running[d2col::RUNNING1][3] =
        gf::Add(
            bad_running[d2col::RUNNING1][3],
            Fp3::One());
    BOOST_CHECK(
        Violations(cs, bad_running) > 0);
}

BOOST_AUTO_TEST_CASE(
    degree2_ctl_rejects_padding_and_terminal_substitution)
{
    BusFixture fixture;
    const auto non_power_schedule =
        fixture.send_schedule;
    const auto non_power =
        rc::BuildRCStage3CtlDegree2Witness(
            non_power_schedule,
            fixture.values,
            fixture.challenges);
    BOOST_CHECK(!non_power.ok);
    const auto empty_cs =
        rc::BuildRCStage3CtlDegree2ConstraintSystem(
            {rc::kRCStage3CtlDegree2Version,
             non_power_schedule,
             fixture.challenges, {}});
    BOOST_CHECK_EQUAL(
        empty_cs.n_columns, 0U);

    rc::RCStage3CtlSchedule exact{{
        {0x44325432U, 0, 1, -1},
        {0x44325432U, 0, 2, -1},
    }};
    const std::vector<Fp3> values{
        gf::FromU64_3(11),
        gf::FromU64_3(22),
    };
    const auto witness =
        rc::BuildRCStage3CtlDegree2Witness(
            exact, values,
            fixture.challenges);
    BOOST_REQUIRE(witness.ok);
    auto wrong_terminal =
        witness.terminal;
    wrong_terminal.alpha1_sum =
        gf::Add(
            wrong_terminal.alpha1_sum,
            Fp3::One());
    const auto cs =
        rc::BuildRCStage3CtlDegree2ConstraintSystem(
            {rc::kRCStage3CtlDegree2Version,
             exact, fixture.challenges,
             wrong_terminal});
    BOOST_REQUIRE_EQUAL(
        cs.n_columns,
        d2col::NUM_COLUMNS);
    BOOST_CHECK(
        Violations(cs, witness.columns) > 0);
}

BOOST_AUTO_TEST_CASE(dual_terminal_composition_cancels_exact_bus)
{
    BusFixture fixture;
    BOOST_CHECK(gf::IsZero(gf::Add(
        fixture.pins[0].terminal.alpha1_sum,
        fixture.pins[1].terminal.alpha1_sum)));
    BOOST_CHECK(gf::IsZero(gf::Add(
        fixture.pins[0].terminal.alpha2_sum,
        fixture.pins[1].terminal.alpha2_sum)));
    std::string why;
    BOOST_CHECK(rc::VerifyRCStage3CtlPublicPinComposition(
        fixture.manifest, fixture.pins, &why));
    BOOST_CHECK(!rc::CommitRCStage3CtlComposition(
                     fixture.manifest, fixture.pins)
                     .IsNull());
}

BOOST_AUTO_TEST_CASE(executable_child_air_proofs_bind_both_epochs_and_terminal)
{
    ExecutableBusFixture fixture;
    const std::vector<rc::RCStage3CtlSchedule> schedules{
        fixture.send_schedule, fixture.receive_schedule};
    std::string why;
    BOOST_REQUIRE(rc::VerifyRCStage3CtlBusAirProofs(
        fixture.manifest, fixture.pins, schedules,
        fixture.proofs, &why));
    BOOST_CHECK(
        why.find("recursive_consumption_pending") != std::string::npos);

    auto substituted_aux = fixture.pins;
    substituted_aux[0].auxiliary_commitment =
        substituted_aux[1].auxiliary_commitment;
    BOOST_CHECK(!rc::VerifyRCStage3CtlBusAirProofs(
        fixture.manifest, substituted_aux, schedules,
        fixture.proofs, &why));
    BOOST_CHECK(
        why.find("auxiliary_epoch_binding") != std::string::npos);

    auto substituted_trace = fixture.pins;
    substituted_trace[0].trace_commitment = Filled(0xab);
    BOOST_CHECK(!rc::VerifyRCStage3CtlBusAirProofs(
        fixture.manifest, substituted_trace, schedules,
        fixture.proofs, &why));
    BOOST_CHECK(
        why.find("challenge_binding") != std::string::npos ||
        why.find("trace_epoch_binding") != std::string::npos);

    auto replayed_proofs = fixture.proofs;
    std::swap(replayed_proofs[0], replayed_proofs[1]);
    BOOST_CHECK(!rc::VerifyRCStage3CtlBusAirProofs(
        fixture.manifest, fixture.pins, schedules,
        replayed_proofs, &why));
    BOOST_CHECK(
        why.find("trace_epoch_binding") != std::string::npos);

    auto replayed_lane = fixture.pins;
    const rc::RCStage3CtlChallenges swapped{
        fixture.challenges.gamma2, fixture.challenges.gamma1,
        fixture.challenges.alpha2, fixture.challenges.alpha1};
    replayed_lane[0].challenge_commitment =
        rc::CommitRCStage3CtlChallenges(swapped);
    BOOST_CHECK(!rc::VerifyRCStage3CtlBusAirProofs(
        fixture.manifest, replayed_lane, schedules,
        fixture.proofs, &why));
    BOOST_CHECK(
        why.find("challenge_binding") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(executable_child_recomputes_committed_schedule_counts)
{
    ExecutableBusFixture fixture;
    auto expanded_schedule = fixture.send_schedule;
    expanded_schedule.events.push_back({7, 2, 11, 1});

    // Keep the prover-declared event/send/receive counts unchanged while
    // rebinding both public copies to the larger committed schedule. Before
    // the verifier-side recount this let the soundness ledger charge E=3 for
    // a proof schedule containing four rational-identity terms.
    auto manifest = fixture.manifest;
    auto pins = fixture.pins;
    const uint256 expanded_commitment =
        rc::CommitRCStage3CtlSchedule(expanded_schedule);
    BOOST_REQUIRE(!expanded_commitment.IsNull());
    manifest.participants[0].schedule_commitment = expanded_commitment;
    pins[0].schedule_commitment = expanded_commitment;

    std::string why;
    BOOST_CHECK(!rc::VerifyRCStage3CtlChildAirProof(
        manifest, pins, 0, expanded_schedule, fixture.proofs[0], &why));
    BOOST_CHECK(why.find("schedule_counts") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(relation_export_is_equal_to_executed_ctl_base_columns)
{
    ExecutableBusFixture fixture;
    const uint256 relation_commitment = Filled(0xc1);
    const auto canonical = RelationExport(
        fixture.pins[0], fixture.proofs[0], relation_commitment);
    std::string why;
    BOOST_REQUIRE(rc::VerifyRCStage3CtlRelationExportBinding(
        canonical, fixture.pins[0], fixture.send_schedule,
        fixture.proofs[0], relation_commitment, &why));
    BOOST_CHECK(
        why.find("relation_witness_equality_pending") !=
        std::string::npos);

    // The generic bridge deliberately treats the relation commitment as an
    // opaque caller-supplied label: it cannot determine whether the relation
    // proof's witness VALUE column has this CTL root.  Demonstrate that exact
    // boundary so this check cannot accidentally be promoted to an authority
    // claim before role-specific relation adapters are implemented.
    const uint256 unrelated_relation_commitment = Filled(0xc4);
    const auto opaque_export = RelationExport(
        fixture.pins[0], fixture.proofs[0],
        unrelated_relation_commitment);
    BOOST_REQUIRE(rc::VerifyRCStage3CtlRelationExportBinding(
        opaque_export, fixture.pins[0], fixture.send_schedule,
        fixture.proofs[0], unrelated_relation_commitment, &why));
    BOOST_CHECK(
        why.find("relation_witness_equality_pending") !=
        std::string::npos);

    std::vector<unsigned char> encoded;
    BOOST_REQUIRE(rc::SerializeRCStage3CtlRelationExportPin(
        canonical, encoded, &why));
    BOOST_CHECK_EQUAL(
        encoded.size(), rc::kRCStage3CtlRelationExportBytes);
    const auto decoded =
        rc::DeserializeRCStage3CtlRelationExportPin(encoded, &why);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(*decoded == canonical);
    BOOST_CHECK(!rc::CommitRCStage3CtlRelationExportPin(
                     canonical)
                     .IsNull());

    auto substituted_value = canonical;
    substituted_value.prechallenge_column_roots[col::VALUE] =
        Filled(0xc2);
    BOOST_CHECK(!rc::VerifyRCStage3CtlRelationExportBinding(
        substituted_value, fixture.pins[0], fixture.send_schedule,
        fixture.proofs[0], relation_commitment, &why));
    BOOST_CHECK(why.find("column_root") != std::string::npos);

    auto relabelled = canonical;
    relabelled.role = rc::RCStage3RelationRole::CoupledGemm;
    BOOST_CHECK(!rc::VerifyRCStage3CtlRelationExportBinding(
        relabelled, fixture.pins[0], fixture.send_schedule,
        fixture.proofs[0], relation_commitment, &why));
    BOOST_CHECK(why.find("public_binding") != std::string::npos);

    auto wrong_relation = canonical;
    wrong_relation.relation_commitment = Filled(0xc3);
    BOOST_CHECK(!rc::VerifyRCStage3CtlRelationExportBinding(
        wrong_relation, fixture.pins[0], fixture.send_schedule,
        fixture.proofs[0], relation_commitment, &why));

    auto wrong_count = canonical;
    ++wrong_count.event_count;
    BOOST_CHECK(!rc::VerifyRCStage3CtlRelationExportBinding(
        wrong_count, fixture.pins[0], fixture.send_schedule,
        fixture.proofs[0], relation_commitment, &why));

    auto trailing = encoded;
    trailing.push_back(0);
    BOOST_CHECK(
        !rc::DeserializeRCStage3CtlRelationExportPin(
             trailing, &why)
             .has_value());
}

BOOST_AUTO_TEST_CASE(logup_accounting_is_exact_and_poles_are_completeness_only)
{
    BusFixture fixture;
    auto second = fixture.manifest;
    second.bus_id++;
    const std::vector<rc::RCStage3CtlManifest> manifests{
        fixture.manifest, second};
    const auto ledger =
        rc::AssessRCStage3CtlSoundness(manifests, 40, 8);
    BOOST_CHECK_EQUAL(ledger.bus_count, 2U);
    BOOST_CHECK_EQUAL(ledger.total_events, 12U);
    // Per bus E=6: [4(E-1)]^2 = 400; two buses contribute 800.
    BOOST_CHECK_EQUAL(
        ledger.dual_lane_false_accept_numerator, 800U);
    BOOST_CHECK_EQUAL(ledger.pole_completeness_numerator, 24U);
    BOOST_CHECK_EQUAL(ledger.algebraic_bits_before_losses, 368U);
    BOOST_CHECK_EQUAL(ledger.false_accept_bits_after_losses, 325U);
    BOOST_CHECK_EQUAL(
        ledger.pole_completeness_bits_after_losses, 141U);
    BOOST_CHECK_EQUAL(
        ledger.sampler_exhaustion_bits_after_losses, 138U);
    BOOST_CHECK(ledger.manifests_exact);
    BOOST_CHECK(ledger.commit_then_challenge);
    BOOST_CHECK(ledger.independent_domain_separated_lanes);
    BOOST_CHECK(ledger.uniform_challenge_sampling);
    BOOST_CHECK(ledger.bounded_challenge_sampling);
    BOOST_CHECK(!ledger.reduction_complete);

    const auto duplicate =
        rc::AssessRCStage3CtlSoundness(
            {fixture.manifest, fixture.manifest}, 40, 8);
    BOOST_CHECK(!duplicate.manifests_exact);

    auto unbalanced = fixture.manifest;
    ++unbalanced.participants[0].send_count;
    ++unbalanced.participants[0].event_count;
    const auto bad =
        rc::AssessRCStage3CtlSoundness({unbalanced}, 40, 1);
    BOOST_CHECK(!bad.manifests_exact);
}

BOOST_AUTO_TEST_CASE(composition_rejects_omission_bus_and_value_mismatch)
{
    BusFixture fixture;
    std::string why;

    auto omitted = fixture.pins;
    omitted.pop_back();
    BOOST_CHECK(!rc::VerifyRCStage3CtlPublicPinComposition(
        fixture.manifest, omitted, &why));

    auto wrong_bus = fixture.pins;
    wrong_bus[1].bus_id++;
    BOOST_CHECK(!rc::VerifyRCStage3CtlPublicPinComposition(
        fixture.manifest, wrong_bus, &why));

    auto wrong_schedule = fixture.pins;
    wrong_schedule[1].schedule_commitment = Filled(0x99);
    BOOST_CHECK(!rc::VerifyRCStage3CtlPublicPinComposition(
        fixture.manifest, wrong_schedule, &why));

    auto altered_values = fixture.values;
    altered_values[2] = gf::Add(altered_values[2], Fp3::One());
    const auto altered = rc::BuildRCStage3CtlWitness(
        fixture.receive_schedule, altered_values, fixture.challenges);
    BOOST_REQUIRE(altered.ok);
    auto wrong_terminal = fixture.pins;
    wrong_terminal[1].terminal = altered.terminal;
    BOOST_CHECK(!rc::VerifyRCStage3CtlPublicPinComposition(
        fixture.manifest, wrong_terminal, &why));
    BOOST_CHECK(why.find("nonzero_terminal") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(challenges_bind_ordered_trace_epoch_without_aux_cycle)
{
    BusFixture fixture;
    rc::RCStage3CtlChallenges original;
    BOOST_REQUIRE(rc::DeriveRCStage3CtlChallenges(
        fixture.manifest, fixture.pins, original));

    auto postproof_mutation = fixture.pins;
    postproof_mutation[0].auxiliary_commitment = Filled(0xaa);
    postproof_mutation[0].terminal.alpha1_sum =
        gf::Add(postproof_mutation[0].terminal.alpha1_sum, Fp3::One());
    rc::RCStage3CtlChallenges unchanged;
    BOOST_REQUIRE(rc::DeriveRCStage3CtlChallenges(
        fixture.manifest, postproof_mutation, unchanged));
    BOOST_CHECK(unchanged == original);

    auto trace_mutation = fixture.pins;
    trace_mutation[0].trace_commitment = Filled(0xbb);
    rc::RCStage3CtlChallenges changed;
    BOOST_REQUIRE(rc::DeriveRCStage3CtlChallenges(
        fixture.manifest, trace_mutation, changed));
    BOOST_CHECK(!(changed == original));
}

BOOST_AUTO_TEST_CASE(child_pin_codec_and_recursive_encoding_are_canonical)
{
    BusFixture fixture;
    std::vector<unsigned char> encoded;
    std::string why;
    BOOST_REQUIRE(
        rc::SerializeRCStage3CtlChildPin(fixture.pins[0], encoded, &why));
    const auto decoded =
        rc::DeserializeRCStage3CtlChildPin(encoded, &why);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(*decoded == fixture.pins[0]);

    auto trailing = encoded;
    trailing.push_back(0);
    BOOST_CHECK(!rc::DeserializeRCStage3CtlChildPin(trailing, &why).has_value());

    // First terminal coordinate starts after the 164-byte fixed prefix.
    auto noncanonical = encoded;
    for (size_t i = 164; i < 172; ++i) noncanonical[i] = 0xff;
    BOOST_CHECK(
        !rc::DeserializeRCStage3CtlChildPin(noncanonical, &why).has_value());

    std::vector<Fp3> recursion_pin;
    BOOST_REQUIRE(rc::EncodeRCStage3CtlChildPinForRecursion(
        fixture.pins[0], recursion_pin, &why));
    BOOST_CHECK_EQUAL(recursion_pin.size(),
                      rc::kRCStage3CtlRecursivePinElements);
    auto mutated = fixture.pins[0];
    mutated.trace_commitment = Filled(0xee);
    std::vector<Fp3> recursion_mutated;
    BOOST_REQUIRE(rc::EncodeRCStage3CtlChildPinForRecursion(
        mutated, recursion_mutated, &why));
    BOOST_REQUIRE_EQUAL(recursion_pin.size(), recursion_mutated.size());
    bool any_difference = false;
    for (size_t i = 0; i < recursion_pin.size(); ++i) {
        any_difference |= !gf::Eq(recursion_pin[i], recursion_mutated[i]);
    }
    BOOST_CHECK(any_difference);
}

BOOST_AUTO_TEST_SUITE_END()
