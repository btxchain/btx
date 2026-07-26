// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_v6_fs.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <string>
#include <vector>

namespace ah = matmul::v4::rc::alg_hash;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace v6 = matmul::v4::rc::stage3_v6_fs;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_v6_fs_tests,
                         BasicTestingSetup)

namespace {

v6::MasterBindingInput MasterInput()
{
    v6::MasterBindingInput input;
    for (uint32_t i = 0; i < input.public_statement_sha256d.size(); ++i) {
        input.public_statement_sha256d[i] =
            static_cast<uint8_t>(3 * i + 1);
    }
    input.batch_columns = 1092;
    input.n_coeffs = 1U << 19;
    input.n_lde = 1U << 23;
    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t limb = 0; limb < ah::kAlgHashDigestLen; ++limb) {
            input.ordered_lane_row_roots[lane][limb] =
                gf::FromU64(100 + 10 * lane + limb);
        }
    }
    return input;
}

std::vector<ah::Digest> NativeFrameDigests(
    const std::vector<v6::Frame>& frames)
{
    std::vector<ah::Digest> out;
    ah::Digest previous{};
    for (uint32_t frame_index = 0; frame_index < frames.size();
         ++frame_index) {
        const auto& frame = frames[frame_index];
        std::vector<gf::Fp> words{
            v6::kTranscriptDomain,
            gf::FromU64(static_cast<uint16_t>(frame.kind)),
            gf::FromU64(frame.lane),
            gf::FromU64(frame.index),
            previous[0], previous[1], previous[2], previous[3],
            gf::FromU64(v6::kVersion),
            gf::FromU64(frame.payload.size())};
        for (const auto& word : frame.payload) {
            words.push_back(word.value);
        }
        previous = ah::SpongeHashFp(words);
        out.push_back(previous);
    }
    return out;
}

v6::Program QueryProgram(uint32_t domain = 1U << 8)
{
    std::vector<v6::Frame> frames;
    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t candidate = 0;
             candidate < v6::kQueryCandidatesPerIndex; ++candidate) {
            v6::Frame frame;
            frame.kind = v6::FrameKind::QueryCandidate;
            frame.lane = lane;
            frame.index = candidate;
            frame.payload.push_back(
                {gf::FromU64(domain),
                 v6::WordOrigin::PublicStatement});
            frames.push_back(std::move(frame));
        }
    }
    return v6::BuildProgram(frames);
}

v6::Program OodProgram()
{
    std::vector<v6::Frame> frames;
    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t candidate = 0; candidate < 4; ++candidate) {
            v6::Frame frame;
            frame.kind = v6::FrameKind::OodCandidate;
            frame.lane = lane;
            frame.index = candidate;
            frames.push_back(std::move(frame));
        }
    }
    return v6::BuildProgram(frames);
}

struct ChildBoundaryExportFixture {
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
};

ChildBoundaryExportFixture ChildBoundaryExports(
    const v6::Program& program)
{
    ChildBoundaryExportFixture out;
    out.cs.n_rows = program.trace_rows;
    out.cs.n_columns = 16;
    out.cs.preprocessed_pin_ood = true;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<gf::Fp3>(out.cs.n_rows, gf::Fp3::Zero()));
    for (uint32_t lane = 0; lane < v6::kRate; ++lane) {
        std::vector<gf::Fp3> expected(
            out.cs.n_rows, gf::Fp3::Zero());
        for (uint32_t row = 0; row < program.trace_rows; ++row) {
            if (program.rows[row].proof_mask[lane]) {
                expected[row] =
                    gf::Fp3::FromFp(program.rows[row].source[lane]);
            }
        }
        out.cs.preprocessed.emplace_back(8 + lane, expected);
        out.columns[lane] = expected;
        out.columns[8 + lane] = expected;

        aq::AirConstraint<gf::Fp3> boundary;
        boundary.name = "test.normalized_child.public_export";
        boundary.kind = aq::AirKind::kEverywhere;
        boundary.alg_degree = 1;
        boundary.eval = [lane](
                            const std::vector<gf::Fp3>& cur,
                            const std::vector<gf::Fp3>&) {
            return gf::Sub(cur[lane], cur[8 + lane]);
        };
        out.cs.constraints.push_back(std::move(boundary));
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(master_lane_program_is_exact_and_poseidon_replayed)
{
    const v6::Program program =
        v6::BuildMasterBindingProgram(MasterInput());
    BOOST_REQUIRE_MESSAGE(program.valid, program.note);
    BOOST_CHECK_EQUAL(program.frames.size(), 3U);
    BOOST_CHECK_EQUAL(program.active_rows, 11U);
    BOOST_CHECK_EQUAL(program.trace_rows, 16U);
    BOOST_CHECK_EQUAL(program.payload_cells.size(), 43U);

    const v6::Layout layout = v6::CanonicalLayout();
    BOOST_CHECK_EQUAL(layout.poseidon.End(), 484U);
    BOOST_CHECK_EQUAL(layout.source_base, 484U);
    BOOST_CHECK_EQUAL(layout.external_source_base, 492U);
    BOOST_CHECK_EQUAL(layout.End(), 697U);

    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        v6::BuildConstraintSystem(program, cs, &why), why);
    BOOST_CHECK_EQUAL(cs.n_rows, 16U);
    BOOST_CHECK_EQUAL(cs.n_columns, 697U);
    // 472 quadratic Poseidon identities + 12 start + 12 continuation +
    // four frame-chain + eight fixed-source + eight proof-source equalities.
    BOOST_CHECK_EQUAL(cs.constraints.size(), 705U);

    const v6::Witness witness = v6::BuildWitness(program);
    BOOST_REQUIRE_MESSAGE(witness.valid, witness.note);
    BOOST_CHECK(witness.proof_payload_equality_hooks_satisfied);
    BOOST_CHECK(!witness.external_sources_owned_by_child_verifier);
    BOOST_CHECK_EQUAL(v6::CountViolations(cs, witness.columns), 0U);
    BOOST_CHECK(witness.frame_digests ==
                NativeFrameDigests(program.frames));

    static_assert(v6::kV6AlgebraicTranscriptAirExecutable);
    static_assert(v6::kV6MasterLaneBindingAirExecutable);
    static_assert(v6::kV6QueryReductionAirExecutable);
    static_assert(v6::kV6ChildProofSourceIntegrationExecutable);
    static_assert(!v6::kV6RecursiveAuthorityReady);
}

BOOST_AUTO_TEST_CASE(fixed_proof_source_and_chain_mutations_are_rejected)
{
    const v6::Program program =
        v6::BuildMasterBindingProgram(MasterInput());
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE(v6::BuildConstraintSystem(program, cs, &why));
    const v6::Witness honest = v6::BuildWitness(program);
    BOOST_REQUIRE(honest.valid);
    const v6::Layout layout = v6::CanonicalLayout();

    // Public boundary/framing cannot be changed by the prover.
    auto fixed = honest.columns;
    fixed[layout.Source(0)][0] =
        gf::Add(fixed[layout.Source(0)][0], gf::Fp3::One());
    BOOST_CHECK_GT(v6::CountViolations(cs, fixed), 0U);

    // A proof-derived row-root source must equal the child-verifier export.
    const auto root_cell = std::find_if(
        program.payload_cells.begin(), program.payload_cells.end(),
        [](const v6::PayloadCell& cell) {
            return cell.origin == v6::WordOrigin::ProofDerived;
        });
    BOOST_REQUIRE(root_cell != program.payload_cells.end());
    auto source = honest.columns;
    source[layout.Source(root_cell->rate_lane)]
          [root_cell->trace_row] =
        gf::Add(
            source[layout.Source(root_cell->rate_lane)]
                  [root_cell->trace_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(v6::CountViolations(cs, source), 0U);

    auto external = honest.columns;
    external[layout.ExternalSource(root_cell->rate_lane)]
            [root_cell->trace_row] =
        gf::Add(
            external[layout.ExternalSource(root_cell->rate_lane)]
                    [root_cell->trace_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(v6::CountViolations(cs, external), 0U);

    // The lane-0 frame header is chained to the exact master digest.
    const uint32_t lane0_start = program.rows[0].end
        ? 1
        : static_cast<uint32_t>(std::find_if(
              program.rows.begin(), program.rows.end(),
              [](const v6::ProgramRow& row) {
                  return row.active && row.frame == 1 && row.start;
              }) - program.rows.begin());
    auto chain = honest.columns;
    chain[layout.Source(4)][lane0_start] =
        gf::Add(chain[layout.Source(4)][lane0_start],
                gf::Fp3::One());
    BOOST_CHECK_GT(v6::CountViolations(cs, chain), 0U);
}

BOOST_AUTO_TEST_CASE(scenario_b_is_selected_but_stays_fail_closed)
{
    const v6::Program program =
        v6::BuildMasterBindingProgram(MasterInput());
    const auto scenarios = v6::AssessScenarios(program, 894);
    BOOST_CHECK(
        scenarios[0].scenario == v6::Scenario::ExistingSha256dAir);
    BOOST_CHECK(scenarios[0].existing_wire_compatible);
    BOOST_CHECK(!scenarios[0].production_authority_ready);

    BOOST_CHECK(scenarios[1].scenario == v6::Scenario::AlgebraicV6);
    BOOST_CHECK(scenarios[1].algebraic_transcript_in_air);
    BOOST_CHECK(scenarios[1].master_and_lane_binding_in_air);
    BOOST_CHECK(scenarios[1].proof_payload_equality_seam);
    BOOST_CHECK(scenarios[1].host_digest_trust_removed);
    BOOST_CHECK(scenarios[1].query_reduction_closed);
    BOOST_CHECK(scenarios[1].child_source_integration_closed);
    BOOST_CHECK(!scenarios[1].production_authority_ready);
    BOOST_CHECK_EQUAL(scenarios[1].trace_width, 697U);
    BOOST_CHECK_EQUAL(
        scenarios[1].permutation_or_compression_rows,
        program.active_rows);

    BOOST_CHECK(scenarios[2].scenario ==
                v6::Scenario::HostDigestHybrid);
    BOOST_CHECK(!scenarios[2].proof_payload_equality_seam);
    BOOST_CHECK(!scenarios[2].host_digest_trust_removed);
    BOOST_CHECK(!scenarios[2].production_authority_ready);
}

BOOST_AUTO_TEST_CASE(production_v6_schedule_is_finite_and_exact)
{
    const auto master = MasterInput();
    v6::FullTranscriptInput input;
    input.master = master;
    input.folds = 19;
    input.queries = 128;
    for (uint32_t lane = 0; lane < 2; ++lane) {
        auto& proof = input.lane[lane];
        for (uint32_t limb = 0; limb < ah::kAlgHashDigestLen; ++limb) {
            proof.trace_root[limb] =
                gf::FromU64(200 + 10 * lane + limb);
        }
        proof.row_root = master.ordered_lane_row_roots[lane];
        proof.evals_z1.assign(
            master.batch_columns,
            gf::Fp3{gf::FromU64(301 + lane), 302, 303});
        proof.evals_z2.assign(
            master.batch_columns,
            gf::Fp3{gf::FromU64(401 + lane), 402, 403});
        proof.fold_roots.resize(input.folds);
        for (uint32_t fold = 0; fold < input.folds; ++fold) {
            for (uint32_t limb = 0;
                 limb < ah::kAlgHashDigestLen; ++limb) {
                proof.fold_roots[fold][limb] =
                    gf::FromU64(
                        500 + 100 * lane + 4 * fold + limb);
            }
        }
    }

    const v6::Program program =
        v6::BuildFullTranscriptProgram(input);
    BOOST_REQUIRE_MESSAGE(program.valid, program.note);
    BOOST_CHECK_EQUAL(program.frames.size(), 3305U);
    BOOST_CHECK_EQUAL(program.active_rows, 8253U);
    BOOST_CHECK_EQUAL(program.trace_rows, 16384U);
    BOOST_CHECK_EQUAL(program.payload_cells.size(), 14331U);

    // Every non-master challenge is a zero-payload, chained frame.  No
    // host-carried challenge value is accepted as input to the V6 AIR.
    const auto challenge_count = std::count_if(
        program.frames.begin(), program.frames.end(),
        [](const v6::Frame& frame) {
            return frame.kind == v6::FrameKind::BatchCoefficient ||
                   frame.kind == v6::FrameKind::OodCandidate ||
                   frame.kind == v6::FrameKind::DeepWeight ||
                   frame.kind == v6::FrameKind::FoldChallenge ||
                   frame.kind == v6::FrameKind::QueryCandidate ||
                   frame.kind ==
                       v6::FrameKind::AirQuotientChallenge;
        });
    BOOST_CHECK_EQUAL(
        challenge_count,
        2U * (master.batch_columns + 4 + 2 +
              input.folds +
              v6::kQueryCandidatesPerIndex * input.queries + 1));
}

BOOST_AUTO_TEST_CASE(two_row_transcript_air_proves_and_verifies)
{
    v6::Frame frame;
    frame.kind = v6::FrameKind::MasterStatement;
    const v6::Program program = v6::BuildProgram({frame});
    BOOST_REQUIRE(program.valid);
    BOOST_CHECK_EQUAL(program.active_rows, 2U);
    BOOST_CHECK_EQUAL(program.trace_rows, 2U);

    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        v6::BuildConstraintSystem(program, cs, &why), why);
    const v6::Witness witness = v6::BuildWitness(program);
    BOOST_REQUIRE_MESSAGE(witness.valid, witness.note);

    uint256 seed;
    std::fill(seed.begin(), seed.end(), 0x96);
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            cs, witness.columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_CHECK_MESSAGE(
        (aq::AirQuotientVerify<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            cs, proved.proof, seed, &why)),
        why);
}

BOOST_AUTO_TEST_CASE(
    fixed_four_candidate_query_sampler_is_exact_and_mutation_safe)
{
    const v6::Program program = QueryProgram();
    BOOST_REQUIRE_MESSAGE(program.valid, program.note);
    BOOST_CHECK_EQUAL(program.query_domain_bits, 8U);
    BOOST_CHECK_EQUAL(program.active_rows, 16U);
    BOOST_CHECK_EQUAL(program.trace_rows, 16U);

    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        v6::BuildConstraintSystem(program, cs, &why), why);
    const v6::Witness honest = v6::BuildWitness(program);
    BOOST_REQUIRE_MESSAGE(honest.valid, honest.note);
    BOOST_CHECK_EQUAL(v6::CountViolations(cs, honest.columns), 0U);

    const auto reductions =
        v6::ExtractQueryReductions(program, honest);
    BOOST_REQUIRE_EQUAL(reductions.size(), 2U);
    const v6::Layout layout = v6::CanonicalLayout();
    for (uint32_t lane = 0; lane < 2; ++lane) {
        BOOST_CHECK(reductions[lane].valid);
        BOOST_CHECK_EQUAL(reductions[lane].lane, lane);
        BOOST_CHECK_EQUAL(reductions[lane].query, 0U);
        BOOST_CHECK_LT(reductions[lane].selected_candidate, 4U);
        BOOST_CHECK_LT(reductions[lane].reduced_index, 256U);
    }

    const auto assessment = v6::AssessQuerySampler(1U << 23);
    BOOST_CHECK(assessment.exact_power_of_two_reduction);
    BOOST_CHECK(assessment.air_executable);
    BOOST_CHECK_EQUAL(
        assessment.rejection_threshold, gf::kP - 1);
    BOOST_CHECK_GT(assessment.exhaustion_bits_after_sites, 229.9L);
    BOOST_CHECK(!assessment.global_transcript_independence_proved);
    BOOST_CHECK(!v6::AssessQuerySampler(3).air_executable);

    const auto final_row = std::find_if(
        program.rows.begin(), program.rows.end(),
        [](const v6::ProgramRow& row) {
            return row.query_group_final;
        });
    BOOST_REQUIRE(final_row != program.rows.end());
    const uint32_t row = static_cast<uint32_t>(
        final_row - program.rows.begin());

    auto bit = honest.columns;
    bit[layout.QueryBit(0)][row] =
        gf::Sub(gf::Fp3::One(), bit[layout.QueryBit(0)][row]);
    BOOST_CHECK_GT(v6::CountViolations(cs, bit), 0U);

    auto selected = honest.columns;
    selected[layout.query_selected][row] =
        gf::Sub(
            gf::Fp3::One(),
            selected[layout.query_selected][row]);
    BOOST_CHECK_GT(v6::CountViolations(cs, selected), 0U);

    auto reduced = honest.columns;
    reduced[layout.query_reduced_index][row] =
        gf::Add(
            reduced[layout.query_reduced_index][row],
            gf::Fp3::One());
    BOOST_CHECK_GT(v6::CountViolations(cs, reduced), 0U);

    // The explicit exhausted-pool state cannot satisfy the final-row
    // completion equation. In an actual transcript this state occurs iff all
    // four canonical candidates equal p-1.
    auto exhausted = honest.columns;
    for (uint32_t r = 0; r < program.trace_rows; ++r) {
        if (!program.rows[r].query_candidate_end) continue;
        exhausted[layout.query_valid][r] = gf::Fp3::Zero();
        exhausted[layout.query_selected][r] = gf::Fp3::Zero();
        exhausted[layout.query_have_selected][r] =
            gf::Fp3::Zero();
        exhausted[layout.query_index_term][r] = gf::Fp3::Zero();
        exhausted[layout.query_index_accumulator][r] =
            gf::Fp3::Zero();
        exhausted[layout.query_reduced_index][r] =
            gf::Fp3::Zero();
    }
    std::vector<gf::Fp3> exhausted_cur(cs.n_columns);
    std::vector<gf::Fp3> exhausted_next(cs.n_columns);
    for (uint32_t column = 0; column < cs.n_columns; ++column) {
        exhausted_cur[column] = exhausted[column][row];
        exhausted_next[column] =
            exhausted[column][(row + 1) % cs.n_rows];
    }
    const auto completion = std::find_if(
        cs.constraints.begin(), cs.constraints.end(),
        [](const aq::AirConstraint<gf::Fp3>& constraint) {
            return constraint.name != nullptr &&
                   std::string(constraint.name) ==
                       "stage3.v6_fs.query.fixed_pool_not_exhausted";
        });
    BOOST_REQUIRE(completion != cs.constraints.end());
    BOOST_CHECK(
        !gf::IsZero(completion->eval(exhausted_cur, exhausted_next)));
    BOOST_CHECK_GT(v6::CountViolations(cs, exhausted), 0U);

    uint256 seed;
    std::fill(seed.begin(), seed.end(), 0x67);
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            cs, honest.columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_CHECK_MESSAGE(
        (aq::AirQuotientVerify<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            cs, proved.proof, seed, &why)),
        why);
}

BOOST_AUTO_TEST_CASE(
    bounded_dual_ood_selection_outputs_are_air_bound_and_mutation_safe)
{
    const v6::Program program = OodProgram();
    BOOST_REQUIRE_MESSAGE(program.valid, program.note);
    BOOST_CHECK_EQUAL(program.active_rows, 16U);
    BOOST_CHECK_EQUAL(program.trace_rows, 16U);

    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        v6::BuildConstraintSystem(program, cs, &why), why);
    const v6::Witness honest = v6::BuildWitness(program);
    BOOST_REQUIRE_MESSAGE(honest.valid, honest.note);
    BOOST_CHECK_EQUAL(v6::CountViolations(cs, honest.columns), 0U);

    const auto selections =
        v6::ExtractOodSelections(program, honest);
    BOOST_REQUIRE_EQUAL(selections.size(), 2U);
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const auto& selected = selections[lane];
        BOOST_CHECK(selected.valid);
        BOOST_CHECK_EQUAL(selected.lane, lane);
        BOOST_CHECK_LT(selected.z1_candidate, 2U);
        BOOST_CHECK_GE(selected.z2_candidate, 2U);
        BOOST_CHECK_LT(selected.z2_candidate, 4U);
        BOOST_CHECK(selected.z1.c1 != 0 || selected.z1.c2 != 0);
        BOOST_CHECK(selected.z2.c1 != 0 || selected.z2.c2 != 0);
        BOOST_CHECK(
            !gf::Eq(selected.z1, selected.z2));
    }

    const v6::Layout layout = v6::CanonicalLayout();
    auto output = honest.columns;
    output[layout.OodAcceptedZ1(0)]
          [selections[0].z1_trace_row] =
        gf::Add(
            output[layout.OodAcceptedZ1(0)]
                  [selections[0].z1_trace_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(v6::CountViolations(cs, output), 0U);

    const auto selected_row = std::find_if(
        program.rows.begin(), program.rows.end(),
        [&](const v6::ProgramRow& row) {
            if (!row.ood_candidate_end) return false;
            const uint32_t index = static_cast<uint32_t>(
                &row - program.rows.data());
            return gf::Eq(
                honest.columns[layout.ood_selected][index],
                gf::Fp3::One());
        });
    BOOST_REQUIRE(selected_row != program.rows.end());
    const uint32_t row = static_cast<uint32_t>(
        selected_row - program.rows.begin());

    auto selector = honest.columns;
    selector[layout.ood_selected][row] = gf::Fp3::Zero();
    BOOST_CHECK_GT(v6::CountViolations(cs, selector), 0U);

    auto inverse = honest.columns;
    inverse[layout.ood_c1_inverse][row] =
        gf::Add(
            inverse[layout.ood_c1_inverse][row],
            gf::Fp3::One());
    BOOST_CHECK_GT(v6::CountViolations(cs, inverse), 0U);

    std::vector<v6::Frame> incomplete(3);
    for (uint32_t i = 0; i < incomplete.size(); ++i) {
        incomplete[i].kind = v6::FrameKind::OodCandidate;
        incomplete[i].index = i;
    }
    BOOST_CHECK(!v6::BuildProgram(incomplete).valid);

    static_assert(v6::kV6OodSelectionAirExecutable);
    static_assert(!v6::kV6RecursiveAuthorityReady);
}

BOOST_AUTO_TEST_CASE(
    direct_alias_uses_child_export_cells_without_host_mirror)
{
    const v6::Program program =
        v6::BuildMasterBindingProgram(MasterInput());
    BOOST_REQUIRE(program.valid);
    const ChildBoundaryExportFixture child =
        ChildBoundaryExports(program);

    aq::AirConstraintSystem<gf::Fp3> combined;
    v6::DirectAliasComposition composition;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        v6::BuildDirectAliasConstraintSystem(
            program, child.cs, 0, combined, &composition, &why),
        why);
    BOOST_CHECK(composition.valid);
    BOOST_CHECK(composition.same_trace);
    BOOST_CHECK(composition.direct_alias);
    BOOST_CHECK_EQUAL(
        composition.transcript.external_source_base, 0U);
    BOOST_CHECK_EQUAL(
        combined.constraints.size(),
        child.cs.constraints.size() + 705U);

    const v6::Witness honest = v6::BuildDirectAliasWitness(
        program, child.cs, child.columns, 0);
    BOOST_REQUIRE_MESSAGE(honest.valid, honest.note);
    BOOST_CHECK(honest.external_sources_owned_by_child_verifier);
    BOOST_CHECK_EQUAL(
        v6::CountViolations(combined, honest.columns), 0U);

    const auto root_cell = std::find_if(
        program.payload_cells.begin(), program.payload_cells.end(),
        [](const v6::PayloadCell& cell) {
            return cell.origin == v6::WordOrigin::ProofDerived;
        });
    BOOST_REQUIRE(root_cell != program.payload_cells.end());
    const auto& layout = composition.transcript;

    auto source = honest.columns;
    source[layout.Source(root_cell->rate_lane)]
          [root_cell->trace_row] =
        gf::Add(
            source[layout.Source(root_cell->rate_lane)]
                  [root_cell->trace_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(v6::CountViolations(combined, source), 0U);

    auto child_export = honest.columns;
    child_export[root_cell->rate_lane][root_cell->trace_row] =
        gf::Add(
            child_export[root_cell->rate_lane]
                        [root_cell->trace_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        v6::CountViolations(combined, child_export), 0U);

    // Changing both sides of the transcript equality still violates the
    // normalized child's public-output boundary equation.
    auto both = honest.columns;
    both[layout.Source(root_cell->rate_lane)]
        [root_cell->trace_row] =
        gf::Add(
            both[layout.Source(root_cell->rate_lane)]
                [root_cell->trace_row],
            gf::Fp3::One());
    both[root_cell->rate_lane][root_cell->trace_row] =
        gf::Add(
            both[root_cell->rate_lane][root_cell->trace_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(v6::CountViolations(combined, both), 0U);

    uint256 seed;
    std::fill(seed.begin(), seed.end(), 0x6a);
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            combined, honest.columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_CHECK_MESSAGE(
        (aq::AirQuotientVerify<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            combined, proved.proof, seed, &why)),
        why);

    static_assert(v6::kV6DirectAliasComposerExecutable);
    static_assert(v6::kV6ChildProofSourceIntegrationExecutable);
    static_assert(!v6::kV6RecursiveAuthorityReady);
}

BOOST_AUTO_TEST_CASE(production_v6_quotient_roundtrip_opt_in)
{
    if (std::getenv("BTX_RUN_STAGE3_V6_PRODUCTION_BENCH") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_V6_PRODUCTION_BENCH=1 for the "
            "W=1092,Q=128,folds=19 V6 quotient roundtrip");
        return;
    }

    v6::FullTranscriptInput input;
    input.master = MasterInput();
    input.folds = 19;
    input.queries = 128;
    for (uint32_t lane = 0; lane < 2; ++lane) {
        auto& proof = input.lane[lane];
        for (uint32_t limb = 0; limb < ah::kAlgHashDigestLen; ++limb) {
            proof.trace_root[limb] =
                gf::FromU64(900 + 10 * lane + limb);
        }
        proof.row_root =
            input.master.ordered_lane_row_roots[lane];
        proof.evals_z1.assign(
            input.master.batch_columns,
            gf::Fp3{gf::FromU64(1001 + lane), 1002, 1003});
        proof.evals_z2.assign(
            input.master.batch_columns,
            gf::Fp3{gf::FromU64(1101 + lane), 1102, 1103});
        proof.fold_roots.resize(input.folds);
        for (uint32_t fold = 0; fold < input.folds; ++fold) {
            for (uint32_t limb = 0;
                 limb < ah::kAlgHashDigestLen; ++limb) {
                proof.fold_roots[fold][limb] =
                    gf::FromU64(
                        1200 + 100 * lane + 4 * fold + limb);
            }
        }
    }

    using Clock = std::chrono::steady_clock;
    const v6::Program program =
        v6::BuildFullTranscriptProgram(input);
    BOOST_REQUIRE_MESSAGE(program.valid, program.note);
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        v6::BuildConstraintSystem(program, cs, &why), why);
    const auto witness_start = Clock::now();
    const v6::Witness witness = v6::BuildWitness(program);
    const auto witness_end = Clock::now();
    BOOST_REQUIRE_MESSAGE(witness.valid, witness.note);

    uint256 seed;
    std::fill(seed.begin(), seed.end(), 0x76);
    const auto prove_start = Clock::now();
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            cs, witness.columns, seed, {});
    const auto prove_end = Clock::now();
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    const auto verify_start = Clock::now();
    BOOST_REQUIRE_MESSAGE(
        (aq::AirQuotientVerify<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            cs, proved.proof, seed, &why)),
        why);
    const auto verify_end = Clock::now();

    const auto millis = [](auto a, auto b) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   b - a)
            .count();
    };
    BOOST_TEST_MESSAGE(
        "V6 production transcript quotient only (not child verifier or "
        "episode): width="
        << cs.n_columns << ", rows=" << cs.n_rows
        << ", constraints=" << cs.constraints.size()
        << ", witness_ms=" << millis(witness_start, witness_end)
        << ", prove_ms=" << millis(prove_start, prove_end)
        << ", verify_ms=" << millis(verify_start, verify_end));
}

BOOST_AUTO_TEST_SUITE_END()
