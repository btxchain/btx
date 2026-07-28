// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_p2_consumer_bridge.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_unified_verifier_air.h>

#include <hash.h>

#include <algorithm>
#include <utility>

namespace matmul::v4::rc::stage3_multirow_v11_unified_verifier_air {
namespace {

namespace backend = stage3_multirow_v11_backend;
namespace cb = constraint_bytecode;
namespace consumer = stage3_multirow_p2_consumer_bridge;
namespace tp = stage3_multirow_p2_transcript;
inline constexpr uint32_t kFixtureTraceRows = 1024;

uint256 H(uint32_t tag)
{
    HashWriter hash;
    hash << uint64_t{0x31564649'4e553631ULL};
    hash << tag;
    return hash.GetHash();
}

aq::AirConstraintSystem<gf::Fp3> TransitionAir()
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = kFixtureTraceRows;
    cs.n_columns = 2;
    cs.constraints.push_back({
        "counter_step", aq::AirKind::kTransition, 1,
        [](const auto& current, const auto& next) {
            return gf::Sub(
                gf::Sub(next[0], current[0]),
                gf::Fp3::One());
        }});
    cs.constraints.push_back({
        "double_counter", aq::AirKind::kEverywhere, 1,
        [](const auto& current, const auto&) {
            return gf::Sub(
                current[1],
                gf::Mul(current[0], gf::Fp3::FromFp(2)));
        }});
    return cs;
}

std::vector<std::vector<gf::Fp3>> TransitionTrace()
{
    std::vector<std::vector<gf::Fp3>> out(
        2, std::vector<gf::Fp3>(
            kFixtureTraceRows));
    for (uint32_t row = 0;
         row < kFixtureTraceRows; ++row) {
        out[0][row] = gf::Fp3::FromFp(row + 11);
        out[1][row] =
            gf::Mul(out[0][row], gf::Fp3::FromFp(2));
    }
    return out;
}

cb::Instruction Load(cb::Opcode opcode, uint32_t column)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = column;
    return out;
}

cb::Instruction Constant(uint64_t value)
{
    cb::Instruction out;
    out.opcode = cb::Opcode::Constant;
    out.constant = gf::Fp3::FromFp(value);
    return out;
}

cb::Instruction Binary(
    cb::Opcode opcode, uint32_t lhs, uint32_t rhs)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = lhs;
    out.rhs = rhs;
    return out;
}

cb::ProgramTable TransitionPrograms()
{
    cb::Program step;
    step.role = RCStage3RelationRole::EpisodeGemm;
    step.constraint_ordinal = 0;
    step.kind = aq::AirKind::kTransition;
    step.declared_degree = 1;
    step.current_width = 2;
    step.next_width = 2;
    step.instructions = {
        Load(cb::Opcode::Next, 0),
        Load(cb::Opcode::Current, 0),
        Binary(cb::Opcode::Sub, 0, 1),
        Constant(1),
        Binary(cb::Opcode::Sub, 2, 3),
    };

    cb::Program twice;
    twice.role = RCStage3RelationRole::EpisodeGemm;
    twice.constraint_ordinal = 1;
    twice.kind = aq::AirKind::kEverywhere;
    twice.declared_degree = 1;
    twice.current_width = 2;
    twice.next_width = 2;
    twice.instructions = {
        Load(cb::Opcode::Current, 1),
        Load(cb::Opcode::Current, 0),
        Constant(2),
        Binary(cb::Opcode::Mul, 1, 2),
        Binary(cb::Opcode::Sub, 0, 3),
    };

    cb::ProgramTable out;
    out.role = RCStage3RelationRole::EpisodeGemm;
    out.current_width = 2;
    out.next_width = 2;
    out.programs = {step, twice};
    return out;
}

tp::StatementV1 StatementFromProof(
    const backend::ProofV1& proof)
{
    tp::StatementV1 out;
    const auto& envelope = proof.envelope;
    const auto& split = envelope.split;
    const auto& batch = split.batch;
    for (uint32_t word = 0;
         word < envelope.public_fs_seed.size(); ++word) {
        for (uint32_t byte = 0; byte < 4; ++byte) {
            out.public_fs_seed.data()[4 * word + byte] =
                static_cast<unsigned char>(
                    envelope.public_fs_seed[word] >>
                    (8 * byte));
        }
    }
    out.pow_grind_nonce = batch.pow_grind_nonce;
    out.trace_rows = split.trace_rows;
    out.trace_columns = envelope.trace_columns;
    out.quotient_len = envelope.quotient_len;
    out.n_coeffs = batch.n_coeffs;
    out.blowup = batch.blowup;
    out.base_column_indices = split.base_column_indices;
    for (uint32_t group = 0;
         group < out.groups.size(); ++group) {
        out.groups[group] = {
            batch.groups[group].role,
            batch.groups[group].first_column,
            batch.groups[group].column_count,
            batch.groups[group].row_commit.n_leaves,
            batch.groups[group].row_commit.root};
    }
    out.column_len = batch.column_len;
    out.evals_z1 = batch.evals_z1;
    out.evals_z2 = batch.evals_z2;
    for (const auto& fold : batch.fold_layers) {
        out.folds.push_back(
            {fold.n_leaves, fold.root});
    }
    out.final_value = batch.final_value;
    return out;
}

rv::InputV1 ActualInput()
{
    rv::InputV1 out;
    const auto cs = TransitionAir();
    const auto proved = backend::ProveAirQuotientV1(
        cs, TransitionTrace(), {0}, H(100));
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    out.proof = proved.proximity.proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        backend::VerifyV1(
            out.proof, &out.transcript, &why),
        why);
    out.child_program = TransitionPrograms();
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            out.child_program, &why),
        why);
    out.expected_child_program_root =
        cb::CommitProgramTableAlgHash(
            out.child_program);

    std::vector<uint32_t> words;
    BOOST_REQUIRE_MESSAGE(
        abi::EncodeCanonicalV1(
            out.proof.envelope,
            words, nullptr, &why),
        why);
    const auto decoded =
        abi::DecodeCanonicalV1(words, &why);
    BOOST_REQUIRE_MESSAGE(
        decoded.has_value(), why);
    const auto replay =
        tp::BuildProductV1(
            StatementFromProof(out.proof));
    BOOST_REQUIRE_MESSAGE(
        replay.valid, replay.note);
    const auto bridged =
        consumer::BuildProductV1(replay);
    BOOST_REQUIRE_MESSAGE(
        bridged.valid, bridged.note);
    uint32_t parent_column = 100;
    for (const auto& source : decoded->sources) {
        if (source.ownership ==
            abi::OwnershipClassV1::PublicStatement) {
            out.parent_public.push_back({
                source.key,
                parent_column++,
                source.value});
        }
    }
    out.parent_join = pj::BuildProductV1(
        *decoded, out.parent_public,
        replay, bridged);
    BOOST_REQUIRE_MESSAGE(
        out.parent_join.valid,
        out.parent_join.note);
    out.expected_child_statement_root =
        ComputeParentJoinStatementManifestR0RootV1(
            out.parent_join, nullptr, &why);
    BOOST_REQUIRE_MESSAGE(
        !out.expected_child_statement_root.IsNull(),
        why);
    return out;
}

mf::ShardProductV1 OneQueryMerkleShard(
    const rv::InputV1& input)
{
    std::vector<uint32_t> words;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        abi::EncodeCanonicalV1(
            input.proof.envelope,
            words, nullptr, &why),
        why);
    const auto decoded =
        abi::DecodeCanonicalV1(
            words, &why);
    BOOST_REQUIRE_MESSAGE(
        decoded.has_value(), why);
    auto shard = mf::BuildShardV1(
        *decoded, input.transcript, 0, 1);
    BOOST_REQUIRE_MESSAGE(
        shard.valid, shard.note);
    return shard;
}

dj::ProductV1 OneQueryDecoder(
    const rv::InputV1& input,
    const mf::ShardProductV1& shard)
{
    std::vector<uint32_t> words;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        abi::EncodeCanonicalV1(
            input.proof.envelope,
            words, nullptr, &why),
        why);
    const auto decoded =
        abi::DecodeCanonicalV1(
            words, &why);
    BOOST_REQUIRE_MESSAGE(
        decoded.has_value(), why);
    auto decoder = dj::BuildProductV1(
        *decoded, input.parent_join,
        {shard});
    BOOST_REQUIRE_MESSAGE(
        decoder.valid, decoder.note);
    return decoder;
}

dvm::ProductV1 OneQueryDeepVm(
    const rv::InputV1& input)
{
    auto product = dvm::BuildProductV1(
        input.proof,
        input.transcript,
        input.child_program,
        input.expected_child_program_root,
        0, 1);
    BOOST_REQUIRE_MESSAGE(
        product.valid, product.note);
    return product;
}

std::vector<gf::Fp3> DecoderChallengeVector(
    const dj::ProductV1& decoder)
{
    return {
        decoder.gamma[0],
        decoder.gamma[1],
        decoder.alpha[0],
        decoder.alpha[1],
    };
}

uint32_t DecoderAuxColumn(
    const dj::LayoutV1& layout,
    uint32_t lane,
    uint32_t side,
    uint32_t stage)
{
    return layout.n_columns +
        ((lane * 2 + side) *
             kDecoderHornerStagesV1 +
         stage);
}

void FillDecoderHornerRow(
    const dj::LayoutV1& layout,
    const std::vector<gf::Fp3>& challenge,
    std::vector<gf::Fp3>& row)
{
    BOOST_REQUIRE_EQUAL(
        challenge.size(),
        kDecoderChallengeColumnsV1);
    BOOST_REQUIRE_EQUAL(
        row.size(),
        layout.n_columns +
            kDecoderHornerAuxColumnsV1);
    for (uint32_t lane = 0;
         lane < dj::kDecoderJoinBusLanesV1;
         ++lane) {
        const auto gamma =
            challenge[lane];
        const auto alpha =
            challenge[2 + lane];
        for (uint32_t side = 0;
             side < 2; ++side) {
            const uint32_t kind =
                side == 0
                ? layout.source_kind
                : layout.consumer_kind;
            const uint32_t occurrence =
                side == 0
                ? layout.source_occurrence
                : layout.consumer_occurrence;
            const uint32_t address =
                side == 0
                ? layout.source_address
                : layout.consumer_address;
            const uint32_t value =
                side == 0
                ? layout.source_value
                : layout.consumer_claim;
            const auto h1 = gf::Add(
                row[address],
                gf::Mul(gamma, row[value]));
            const auto h2 = gf::Add(
                row[occurrence],
                gf::Mul(gamma, h1));
            const auto h3 = gf::Add(
                row[kind],
                gf::Mul(gamma, h2));
            const auto term = gf::Add(
                alpha,
                gf::Mul(gamma, h3));
            row[DecoderAuxColumn(
                layout, lane, side, 0)] = h1;
            row[DecoderAuxColumn(
                layout, lane, side, 1)] = h2;
            row[DecoderAuxColumn(
                layout, lane, side, 2)] = h3;
            row[DecoderAuxColumn(
                layout, lane, side, 3)] = term;
        }
    }
}

uint32_t DeepVmSsaHornerColumn(
    const dvm::LayoutV1& layout,
    uint32_t lane,
    uint32_t side,
    uint32_t stage)
{
    BOOST_REQUIRE_LT(
        lane, kDeepVmRegisterBusLanesV1);
    BOOST_REQUIRE_LT(
        side, kDeepVmRegisterBusSidesV1);
    BOOST_REQUIRE_LT(
        stage, kDeepVmRegisterHornerStagesV1);
    return
        layout.n_columns +
        kDeepVmSsaScheduleColumnsV1 +
        ((lane *
              kDeepVmRegisterBusSidesV1 +
          side) *
             kDeepVmRegisterHornerStagesV1 +
         stage);
}

uint32_t DeepVmSsaInverseColumn(
    const dvm::LayoutV1& layout,
    uint32_t lane,
    uint32_t side)
{
    BOOST_REQUIRE_LT(
        lane, kDeepVmRegisterBusLanesV1);
    BOOST_REQUIRE_LT(
        side, kDeepVmRegisterBusSidesV1);
    return
        layout.n_columns +
        kDeepVmSsaScheduleColumnsV1 +
        kDeepVmRegisterBusLanesV1 *
            kDeepVmRegisterBusSidesV1 *
            kDeepVmRegisterHornerStagesV1 +
        lane * kDeepVmRegisterBusSidesV1 +
        side;
}

uint32_t DeepVmSsaRunningColumn(
    const dvm::LayoutV1& layout,
    uint32_t lane)
{
    BOOST_REQUIRE_LT(
        lane, kDeepVmRegisterBusLanesV1);
    return
        layout.n_columns +
        kDeepVmSsaScheduleColumnsV1 +
        kDeepVmRegisterBusLanesV1 *
            kDeepVmRegisterBusSidesV1 *
            (kDeepVmRegisterHornerStagesV1 + 1) +
        lane;
}

void FillDeepVmPaddingSsaV1(
    const dvm::LayoutV1& layout,
    std::vector<std::vector<gf::Fp3>>& columns)
{
    const auto tag =
        gf::FromU64_3(0x52454731U);
    for (uint32_t row = 0;
         row < columns[0].size(); ++row) {
        for (uint32_t lane = 0;
             lane <
                 kDeepVmRegisterBusLanesV1;
             ++lane) {
            for (uint32_t side = 0;
                 side <
                     kDeepVmRegisterBusSidesV1;
                 ++side) {
                columns[
                    DeepVmSsaHornerColumn(
                        layout, lane, side, 3)]
                    [row] = tag;
                columns[
                    DeepVmSsaInverseColumn(
                        layout, lane, side)]
                    [row] = gf::Fp3::Zero();
            }
            columns[
                DeepVmSsaRunningColumn(
                    layout, lane)][row] =
                gf::Fp3::Zero();
        }
    }
}

bool FillDeepVmSsaAuxV1(
    const dvm::LayoutV1& layout,
    const std::vector<gf::Fp3>& challenge,
    std::vector<std::vector<gf::Fp3>>& columns)
{
    if (challenge.size() !=
            kDeepVmChallengeColumnsV1 ||
        columns.size() !=
            layout.n_columns +
                kDeepVmExtensionColumnsV1) {
        return false;
    }
    const uint32_t program =
        layout.n_columns;
    const uint32_t instruction =
        layout.n_columns + 1;
    const uint32_t lhs_reference =
        layout.n_columns + 2;
    const uint32_t rhs_reference =
        layout.n_columns + 3;
    const uint32_t multiplicity =
        layout.n_columns + 4;
    const auto tag =
        gf::FromU64_3(0x52454731U);
    std::array<gf::Fp3, 2> running{
        gf::Fp3::Zero(),
        gf::Fp3::Zero()};
    for (uint32_t row = 0;
         row < columns[0].size(); ++row) {
        const auto binary =
            gf::Add(
                gf::Add(
                    columns[layout.op_add][row],
                    columns[layout.op_sub][row]),
                columns[layout.op_mul][row]);
        const std::array<uint32_t, 3> reg{{
            instruction,
            lhs_reference,
            rhs_reference,
        }};
        const std::array<uint32_t, 3> value{{
            layout.instruction_result,
            layout.operand_lhs,
            layout.operand_rhs,
        }};
        for (uint32_t lane = 0;
             lane < 2; ++lane) {
            std::array<gf::Fp3, 3> inverse{
                gf::Fp3::Zero(),
                gf::Fp3::Zero(),
                gf::Fp3::Zero()};
            for (uint32_t side = 0;
                 side < 3; ++side) {
                const auto h0 = gf::Add(
                    columns[reg[side]][row],
                    gf::Mul(
                        challenge[lane],
                        columns[value[side]][row]));
                const auto h1 = gf::Add(
                    columns[program][row],
                    gf::Mul(
                        challenge[lane], h0));
                const auto h2 = gf::Add(
                    columns[layout.query][row],
                    gf::Mul(
                        challenge[lane], h1));
                const auto h3 = gf::Add(
                    tag,
                    gf::Mul(
                        challenge[lane], h2));
                columns[
                    DeepVmSsaHornerColumn(
                        layout, lane, side, 0)]
                    [row] = h0;
                columns[
                    DeepVmSsaHornerColumn(
                        layout, lane, side, 1)]
                    [row] = h1;
                columns[
                    DeepVmSsaHornerColumn(
                        layout, lane, side, 2)]
                    [row] = h2;
                columns[
                    DeepVmSsaHornerColumn(
                        layout, lane, side, 3)]
                    [row] = h3;
                const auto active =
                    side == 0
                    ? columns[
                          layout.vm_instruction][row]
                    : binary;
                const auto denominator =
                    gf::Add(
                        challenge[2 + lane],
                        h3);
                if (!gf::IsZero(active)) {
                    if (gf::IsZero(denominator)) {
                        return false;
                    }
                    inverse[side] =
                        gf::Inv(denominator);
                }
                columns[
                    DeepVmSsaInverseColumn(
                        layout, lane, side)]
                    [row] = inverse[side];
            }
            columns[
                DeepVmSsaRunningColumn(
                    layout, lane)][row] =
                running[lane];
            const auto producer =
                gf::Mul(
                    columns[multiplicity][row],
                    inverse[0]);
            const auto consumers =
                gf::Mul(
                    binary,
                    gf::Add(
                        inverse[1],
                        inverse[2]));
            running[lane] =
                gf::Add(
                    running[lane],
                    gf::Sub(
                        producer,
                        consumers));
        }
    }
    return gf::IsZero(running[0]) &&
        gf::IsZero(running[1]);
}

std::vector<uint32_t> DecoderManifestColumns(
    const dj::LayoutV1& layout)
{
    return {
        layout.active,
        layout.source_kind,
        layout.source_occurrence,
        layout.source_address,
        layout.consumer_kind,
        layout.consumer_occurrence,
        layout.consumer_address,
        layout.root_active,
        layout.root_kind,
        layout.root_index,
        layout.root_word,
    };
}

std::vector<std::vector<gf::Fp3>>
BuildSyntheticDecoderTrace(
    const dj::LayoutV1& layout,
    const std::vector<gf::Fp3>& challenge,
    uint32_t rows = 8)
{
    const uint32_t width =
        layout.n_columns +
        kDecoderHornerAuxColumnsV1;
    std::vector<std::vector<gf::Fp3>> columns(
        width,
        std::vector<gf::Fp3>(
            rows, gf::Fp3::Zero()));
    for (uint32_t row = 0;
         row < 2; ++row) {
        columns[layout.active][row] =
            gf::Fp3::One();
        columns[layout.source_kind][row] =
            gf::Fp3::FromFp(3 + row);
        columns[layout.source_occurrence][row] =
            gf::Fp3::FromFp(row);
        columns[layout.source_address][row] =
            gf::Fp3::FromFp(40 + row);
        columns[layout.source_value][row] =
            gf::Fp3::FromFp(70 + row);
        columns[layout.consumer_kind][row] =
            columns[layout.source_kind][row];
        columns[layout.consumer_occurrence][row] =
            columns[layout.source_occurrence][row];
        columns[layout.consumer_address][row] =
            columns[layout.source_address][row];
        columns[layout.consumer_pin][row] =
            columns[layout.source_value][row];
        columns[layout.consumer_claim][row] =
            columns[layout.source_value][row];
    }
    for (uint32_t row = 0;
         row < rows; ++row) {
        std::vector<gf::Fp3> values(width);
        for (uint32_t column = 0;
             column < width; ++column) {
            values[column] =
                columns[column][row];
        }
        FillDecoderHornerRow(
            layout, challenge, values);
        for (uint32_t column = 0;
             column < width; ++column) {
            columns[column][row] =
                values[column];
        }
        for (uint32_t lane = 0;
             lane <
                 dj::kDecoderJoinBusLanesV1;
             ++lane) {
            if (gf::Eq(
                    columns[
                        layout.active][row],
                    gf::Fp3::One())) {
                columns[
                    layout.source_inverse[
                        lane]][row] =
                    gf::Inv(
                        columns[
                            DecoderAuxColumn(
                                layout, lane,
                                0, 3)][row]);
                columns[
                    layout.consumer_inverse[
                        lane]][row] =
                    gf::Inv(
                        columns[
                            DecoderAuxColumn(
                                layout, lane,
                                1, 3)][row]);
            }
        }
    }
    for (uint32_t lane = 0;
         lane < dj::kDecoderJoinBusLanesV1;
         ++lane) {
        gf::Fp3 running =
            gf::Fp3::Zero();
        for (uint32_t row = 0;
             row < rows; ++row) {
            columns[
                layout.running[lane]][row] =
                running;
            running = gf::Add(
                running,
                gf::Sub(
                    columns[
                        layout.source_inverse[
                            lane]][row],
                    columns[
                        layout.consumer_inverse[
                            lane]][row]));
        }
    }
    return columns;
}

void InstallDecoderManifest(
    const dj::LayoutV1& layout,
    const std::vector<std::vector<gf::Fp3>>& columns,
    aq::AirConstraintSystem<gf::Fp3>& cs)
{
    for (uint32_t column :
         DecoderManifestColumns(layout)) {
        cs.preprocessed.emplace_back(
            column, columns[column]);
    }
    cs.preprocessed_pin_ood = true;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_unified_verifier_air_tests)

BOOST_AUTO_TEST_CASE(
    acceptance_output_is_ordinary_and_proof_bound)
{
    LayoutV1 layout;
    layout.acceptance = 0;
    layout.phase_first_base = 1;
    layout.n_columns = 2;

    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 8;
    cs.n_columns = layout.n_columns;
    cs.preprocessed_pin_ood = true;
    std::vector<std::vector<gf::Fp3>> columns(
        cs.n_columns,
        std::vector<gf::Fp3>(
            cs.n_rows, gf::Fp3::Zero()));
    columns[layout.acceptance][0] =
        gf::Fp3::One();
    columns[layout.PhaseFirst(
        PhaseV1::ParentJoin)][0] =
            gf::Fp3::One();
    cs.preprocessed.emplace_back(
        layout.PhaseFirst(
            PhaseV1::ParentJoin),
        columns[layout.PhaseFirst(
            PhaseV1::ParentJoin)]);
    alg_hash::Digest acceptance_program_root{};
    std::string bytecode_why;
    BOOST_REQUIRE_MESSAGE(
        AppendAcceptanceOutputConstraintsV1(
            layout, cs,
            &acceptance_program_root,
            &bytecode_why),
        bytecode_why);
    const auto canonical_table =
        BuildAcceptanceProgramTableV1(layout);
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            canonical_table,
            &bytecode_why),
        bytecode_why);
    BOOST_CHECK_EQUAL(
        canonical_table.programs.size(),
        2U);
    BOOST_CHECK(
        cb::CommitProgramTableAlgHash(
            canonical_table) ==
        acceptance_program_root);

    const std::vector<uint32_t> preprocessed{
        layout.PhaseFirst(
            PhaseV1::ParentJoin)};
    BOOST_CHECK(
        std::find(
            preprocessed.begin(),
            preprocessed.end(),
            layout.acceptance) ==
        preprocessed.end());
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            cs, columns),
        0U);

    const auto honest =
        aq::AirQuotientProveRowsSplitRap(
            cs, columns, preprocessed,
            uint256::ONE);
    BOOST_REQUIRE_MESSAGE(honest.ok, honest.note);
    BOOST_REQUIRE(honest.division_exact);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRap(
            cs, honest.proof, preprocessed,
            uint256::ONE, &why),
        why);

    const auto require_rejected =
        [&](std::vector<std::vector<gf::Fp3>>
                forged) {
            BOOST_REQUIRE_GT(
                air_recurse::
                    CountWitnessViolationsOnH(
                        cs, forged),
                0U);
            aq::AirProveOptions options;
            options.force_commit_on_inexact = true;
            const auto forced =
                aq::AirQuotientProveRowsSplitRap(
                    cs, forged, preprocessed,
                    uint256::ONE, options);
            BOOST_REQUIRE_MESSAGE(
                forced.ok, forced.note);
            BOOST_CHECK(!forced.division_exact);
            BOOST_CHECK(
                !aq::AirQuotientVerifyRowsSplitRap(
                    cs, forced.proof,
                    preprocessed,
                    uint256::ONE, &why));
        };

    auto zero = columns;
    zero[layout.acceptance][0] =
        gf::Fp3::Zero();
    require_rejected(std::move(zero));

    auto relocated = columns;
    relocated[layout.acceptance][0] =
        gf::Fp3::Zero();
    relocated[layout.acceptance][1] =
        gf::Fp3::One();
    require_rejected(std::move(relocated));

    // Bytecode substitution attack: prove under a validly encoded but
    // malicious table whose second relation is a-a=0, then verify the proof
    // under the verifier-reconstructed canonical table.  The canonical
    // verifier must reject at proof level; comparing program roots alone is
    // not accepted as evidence.
    auto substituted_table = canonical_table;
    auto& output =
        substituted_table.programs[1];
    cb::Instruction left;
    left.opcode = cb::Opcode::Current;
    left.lhs = layout.acceptance;
    cb::Instruction right = left;
    cb::Instruction subtract;
    subtract.opcode = cb::Opcode::Sub;
    subtract.lhs = 0;
    subtract.rhs = 1;
    output.instructions = {
        left, right, subtract};
    output.declared_degree = 1;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            substituted_table,
            &bytecode_why),
        bytecode_why);
    BOOST_CHECK(
        cb::CommitProgramTableAlgHash(
            substituted_table) !=
        acceptance_program_root);

    aq::AirConstraintSystem<gf::Fp3>
        substituted_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            substituted_table,
            cs.n_rows,
            substituted_cs,
            &bytecode_why),
        bytecode_why);
    substituted_cs.preprocessed_pin_ood = true;
    substituted_cs.preprocessed =
        cs.preprocessed;
    auto substituted_columns = columns;
    substituted_columns[
        layout.acceptance][0] =
            gf::Fp3::Zero();
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            substituted_cs,
            substituted_columns),
        0U);
    const auto substituted_proof =
        aq::AirQuotientProveRowsSplitRap(
            substituted_cs,
            substituted_columns,
            preprocessed,
            uint256::ONE);
    BOOST_REQUIRE_MESSAGE(
        substituted_proof.ok,
        substituted_proof.note);
    BOOST_REQUIRE(
        substituted_proof.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            cs,
            substituted_proof.proof,
            preprocessed,
            uint256::ONE,
            &why));
}

BOOST_AUTO_TEST_CASE(
    scheduler_bytecode_substitution_rejects_at_proof_level)
{
    LayoutV1 layout;
    layout.phase_tag_base = 0;
    layout.phase_first_base =
        layout.phase_tag_base + kPhasesV1;
    layout.phase_last_base =
        layout.phase_first_base + kPhasesV1;
    layout.phase_transition_base =
        layout.phase_last_base + kPhasesV1;
    layout.active =
        layout.phase_transition_base + kPhasesV1;
    layout.acceptance = layout.active + 1;
    layout.n_columns = layout.acceptance + 1;

    const auto canonical_table =
        BuildSchedulerProgramTableV1(layout);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            canonical_table, &why),
        why);
    BOOST_CHECK_EQUAL(
        canonical_table.programs.size(),
        2 + 4 * kPhasesV1);
    aq::AirConstraintSystem<gf::Fp3> canonical_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            canonical_table, 8,
            canonical_cs, &why),
        why);

    std::vector<std::vector<gf::Fp3>> columns(
        layout.n_columns,
        std::vector<gf::Fp3>(
            canonical_cs.n_rows,
            gf::Fp3::Zero()));
    columns[layout.active][0] =
        gf::Fp3::One();
    columns[layout.PhaseTag(
        PhaseV1::ParentJoin)][0] =
            gf::Fp3::One();
    columns[layout.PhaseFirst(
        PhaseV1::ParentJoin)][0] =
            gf::Fp3::One();
    columns[layout.PhaseLast(
        PhaseV1::ParentJoin)][0] =
            gf::Fp3::One();

    // Keep a common, unrelated R0 column so the rejection below is caused by
    // the canonical scheduler equation rather than a changed R0 schedule.
    const std::vector<uint32_t> preprocessed{
        layout.acceptance};
    canonical_cs.preprocessed.emplace_back(
        layout.acceptance,
        columns[layout.acceptance]);
    canonical_cs.preprocessed_pin_ood = true;
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            canonical_cs, columns),
        0U);
    const auto honest =
        aq::AirQuotientProveRowsSplitRap(
            canonical_cs, columns,
            preprocessed, uint256::ONE);
    BOOST_REQUIRE_MESSAGE(
        honest.ok, honest.note);
    BOOST_REQUIRE(honest.division_exact);
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRap(
            canonical_cs, honest.proof,
            preprocessed, uint256::ONE,
            &why),
        why);

    // Replace the one-hot equation with active-active=0.  This remains valid
    // canonical bytecode, but its root differs and its proof must not verify
    // against the locally reconstructed scheduler.
    auto substituted_table = canonical_table;
    auto& one_hot =
        substituted_table.programs[1];
    cb::Instruction left;
    left.opcode = cb::Opcode::Current;
    left.lhs = layout.active;
    cb::Instruction right = left;
    cb::Instruction subtract;
    subtract.opcode = cb::Opcode::Sub;
    subtract.lhs = 0;
    subtract.rhs = 1;
    one_hot.instructions = {
        left, right, subtract};
    one_hot.declared_degree = 1;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            substituted_table, &why),
        why);
    BOOST_CHECK(
        cb::CommitProgramTableAlgHash(
            substituted_table) !=
        cb::CommitProgramTableAlgHash(
            canonical_table));
    aq::AirConstraintSystem<gf::Fp3>
        substituted_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            substituted_table, 8,
            substituted_cs, &why),
        why);
    auto forged = columns;
    forged[layout.PhaseTag(
        PhaseV1::ParentJoin)][0] =
            gf::Fp3::Zero();
    forged[layout.PhaseFirst(
        PhaseV1::ParentJoin)][0] =
            gf::Fp3::Zero();
    forged[layout.PhaseLast(
        PhaseV1::ParentJoin)][0] =
            gf::Fp3::Zero();
    substituted_cs.preprocessed_pin_ood = true;
    substituted_cs.preprocessed.emplace_back(
        layout.acceptance,
        forged[layout.acceptance]);
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            substituted_cs, forged),
        0U);
    const auto malicious =
        aq::AirQuotientProveRowsSplitRap(
            substituted_cs, forged,
            preprocessed, uint256::ONE);
    BOOST_REQUIRE_MESSAGE(
        malicious.ok, malicious.note);
    BOOST_REQUIRE(
        malicious.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            canonical_cs, malicious.proof,
            preprocessed, uint256::ONE,
            &why));
}

BOOST_AUTO_TEST_CASE(
    parent_join_statement_manifest_r0_excludes_tape_and_rejects_substitution)
{
    const auto input = ActualInput();
    std::string why;
    uint32_t static_columns = 0;
    const uint256 honest_root =
        ComputeParentJoinStatementManifestR0RootV1(
            input.parent_join,
            &static_columns, &why);
    BOOST_REQUIRE_MESSAGE(
        !honest_root.IsNull(), why);
    BOOST_CHECK(
        honest_root ==
        input.expected_child_statement_root);
    BOOST_REQUIRE_GE(
        input.parent_join.preprocessed_columns.size(),
        alg_hash::kAlgHashRate +
            alg_hash::kAlgHashDigestLen);
    BOOST_CHECK_EQUAL(
        static_columns,
        input.parent_join.preprocessed_columns.size() -
            alg_hash::kAlgHashRate -
            alg_hash::kAlgHashDigestLen);

    // Values are now ordinary proof tape. Moving a replay value and its
    // local claim together does not alter R0, but the immutable ParentJoin
    // equations still reject the substitution against the public statement.
    auto value_attack = input.parent_join;
    uint32_t public_row = value_attack.cs.n_rows;
    uint32_t public_lane = alg_hash::kAlgHashRate;
    for (uint32_t row = 0;
         row < value_attack.cs.n_rows &&
         public_row == value_attack.cs.n_rows;
         ++row) {
        for (uint32_t lane = 0;
             lane < alg_hash::kAlgHashRate; ++lane) {
            if (gf::Eq(
                    value_attack.columns[
                        value_attack.layout
                            .public_absorb[lane]
                            .active][row],
                    gf::Fp3::One())) {
                public_row = row;
                public_lane = lane;
                break;
            }
        }
    }
    BOOST_REQUIRE_LT(
        public_row, value_attack.cs.n_rows);
    BOOST_REQUIRE_LT(
        public_lane, alg_hash::kAlgHashRate);
    const auto public_slot =
        value_attack.layout.public_absorb[public_lane];
    value_attack.columns[
        value_attack.layout.replay.Absorb(
            public_lane)][public_row] =
        gf::Add(
            value_attack.columns[
                value_attack.layout.replay.Absorb(
                    public_lane)][public_row],
            gf::Fp3::One());
    value_attack.columns[
        public_slot.claim][public_row] =
        gf::Add(
            value_attack.columns[
                public_slot.claim][public_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        pj::RecountViolationsV1(
            value_attack,
            value_attack.columns),
        0U);
    BOOST_CHECK(
        ComputeParentJoinStatementManifestR0RootV1(
            value_attack) == honest_root);

    // Source offsets are immutable manifest data. Relabelling one changes
    // the exact ordered R0 commitment even if the value tape is untouched.
    auto offset_attack = input.parent_join;
    offset_attack.columns[
        public_slot.source_address][public_row] =
        gf::Add(
            offset_attack.columns[
                public_slot.source_address][public_row],
            gf::Fp3::One());
    BOOST_CHECK(
        ComputeParentJoinStatementManifestR0RootV1(
            offset_attack) != honest_root);

    // An externally substituted statement root fails before any large
    // Merkle/DEEP/unified witness is allocated.
    auto statement_attack = input;
    statement_attack.expected_child_statement_root =
        H(0xfeedU);
    const auto rejected =
        BuildProductV1(
            statement_attack,
            {0, 0, kQ96QueriesV1});
    BOOST_CHECK(!rejected.valid_foundation);
    BOOST_CHECK_EQUAL(
        rejected.note,
        "stage3:v11_unified_verifier:"
        "parent_join_statement_root_mismatch");
}

BOOST_AUTO_TEST_CASE(
    parent_join_phase_bytecode_substitution_rejects_at_proof_level)
{
    const auto input = ActualInput();
    cb::ProgramTable canonical_table;
    np::ManifestV1 manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        np::BuildCanonicalProgramTableV1(
            canonical_table,
            &manifest, &why),
        why);
    BOOST_REQUIRE(
        manifest.no_opaque_callbacks);
    BOOST_REQUIRE_EQUAL(
        canonical_table.programs.size(),
        input.parent_join.cs.constraints.size());
    aq::AirConstraintSystem<gf::Fp3>
        canonical_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            canonical_table,
            input.parent_join.cs.n_rows,
            canonical_cs, &why),
        why);

    // The last native ParentJoin equation is the coefficient-active Boolean
    // check.  Leave that one column ordinary in this focused canary so a
    // substituted equation, rather than an R0 mismatch, is the only possible
    // reason the malicious proof can pass its own relation.
    const uint32_t target_column =
        input.parent_join.layout
            .coefficient_active;
    const auto is_proof_tape =
        [&input](uint32_t column) {
            for (uint32_t lane = 0;
                 lane < alg_hash::kAlgHashRate; ++lane) {
                if (column ==
                    input.parent_join.layout.replay.Absorb(
                        lane)) {
                    return true;
                }
            }
            for (uint32_t limb = 0;
                 limb < alg_hash::kAlgHashDigestLen; ++limb) {
                if (column ==
                    input.parent_join.layout.replay.DigestClaim(
                        limb)) {
                    return true;
                }
            }
            return false;
        };
    std::vector<uint32_t> preprocessed;
    for (const auto& [column, values] :
         input.parent_join.cs.preprocessed) {
        if (column == target_column ||
            is_proof_tape(column)) {
            continue;
        }
        canonical_cs.preprocessed.emplace_back(
            column, values);
        preprocessed.push_back(column);
    }
    canonical_cs.preprocessed_pin_ood = true;
    BOOST_REQUIRE_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            canonical_cs,
            input.parent_join.columns),
        0U);

    auto substituted_table = canonical_table;
    auto& substituted =
        substituted_table.programs.back();
    cb::Instruction left;
    left.opcode = cb::Opcode::Current;
    left.lhs = target_column;
    cb::Instruction right = left;
    cb::Instruction subtract;
    subtract.opcode = cb::Opcode::Sub;
    subtract.lhs = 0;
    subtract.rhs = 1;
    substituted.instructions = {
        left, right, subtract};
    substituted.declared_degree = 1;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            substituted_table, &why),
        why);
    BOOST_CHECK(
        cb::CommitProgramTableAlgHash(
            substituted_table) !=
        manifest.program_root);
    aq::AirConstraintSystem<gf::Fp3>
        substituted_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            substituted_table,
            input.parent_join.cs.n_rows,
            substituted_cs, &why),
        why);
    substituted_cs.preprocessed =
        canonical_cs.preprocessed;
    substituted_cs.preprocessed_pin_ood = true;
    auto forged =
        input.parent_join.columns;
    const uint32_t attack_row =
        input.parent_join.cs.n_rows - 1;
    BOOST_REQUIRE(
        gf::IsZero(
            forged[target_column][attack_row]));
    forged[target_column][attack_row] =
        gf::Fp3::FromFp(2);
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            substituted_cs, forged),
        0U);
    BOOST_CHECK_GT(
        air_recurse::CountWitnessViolationsOnH(
            canonical_cs, forged),
        0U);
    const auto malicious =
        aq::AirQuotientProveRowsSplitRap(
            substituted_cs, forged,
            preprocessed, uint256::ONE);
    BOOST_REQUIRE_MESSAGE(
        malicious.ok, malicious.note);
    BOOST_REQUIRE(
        malicious.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            canonical_cs, malicious.proof,
            preprocessed, uint256::ONE,
            &why));
}

BOOST_AUTO_TEST_CASE(
    merkle_hash_static_bytecode_excludes_io_and_rejects_substitution)
{
    const auto input = ActualInput();
    const auto shard =
        OneQueryMerkleShard(input);
    const auto canonical_table =
        BuildMerkleHashProgramTableV1(
            shard.hash_layout);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            canonical_table, &why),
        why);
    BOOST_CHECK_EQUAL(
        canonical_table.programs.size(),
        stage3_poseidon_air::kFixedConstraints +
            alg_hash::kAlgHashT +
            alg_hash::kAlgHashDigestLen);
    BOOST_CHECK_EQUAL(
        canonical_table.programs.size(),
        shard.hash_cs.constraints.size());
    BOOST_CHECK(
        !std::all_of(
            canonical_table.programs.begin(),
            canonical_table.programs.end(),
            [](const cb::Program& program) {
                return program.instructions.empty();
            }));

    aq::AirConstraintSystem<gf::Fp3>
        canonical_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            canonical_table,
            shard.hash_cs.n_rows,
            canonical_cs, &why),
        why);
    BOOST_CHECK(
        canonical_cs.preprocessed.empty());
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            canonical_cs,
            shard.hash_columns),
        0U);
    // Differentially audit every migrated callback on arbitrary full-Fp3
    // rows, not just the honest Poseidon witness where two wrong equations
    // could accidentally vanish together.
    for (uint32_t probe = 0;
         probe < 3; ++probe) {
        std::vector<gf::Fp3> current(
            shard.hash_cs.n_columns);
        std::vector<gf::Fp3> next(
            shard.hash_cs.n_columns);
        for (uint32_t column = 0;
             column < shard.hash_cs.n_columns;
             ++column) {
            current[column] = {
                gf::FromU64(
                    3 + probe * 17 + column),
                gf::FromU64(
                    5 + probe * 19 + 2 * column),
                gf::FromU64(
                    7 + probe * 23 + 3 * column)};
            next[column] = {
                gf::FromU64(
                    11 + probe * 29 + column),
                gf::FromU64(
                    13 + probe * 31 + 2 * column),
                gf::FromU64(
                    17 + probe * 37 + 3 * column)};
        }
        for (uint32_t ordinal = 0;
             ordinal <
                 canonical_table.programs.size();
             ++ordinal) {
            gf::Fp3 interpreted;
            BOOST_REQUIRE_MESSAGE(
                cb::EvaluateProgram(
                    canonical_table.programs[
                        ordinal],
                    current, next,
                    interpreted, &why),
                why);
            const auto native =
                shard.hash_cs.constraints[
                    ordinal].eval(
                        current, next);
            BOOST_CHECK_MESSAGE(
                gf::Eq(interpreted, native),
                "MerkleHash differential mismatch"
                    << " probe=" << probe
                    << " ordinal=" << ordinal);
        }
    }

    // The sixteen hash I/O lanes are ordinary trace cells. Mutating one does
    // not require (or permit) an R0 rewrite; the canonical equality program
    // detects it.
    auto forged = shard.hash_columns;
    const uint32_t input_pin =
        shard.hash_layout.InputPin(0);
    forged[input_pin][0] =
        gf::Add(
            forged[input_pin][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        air_recurse::CountWitnessViolationsOnH(
            canonical_cs, forged),
        0U);

    // A malicious prover can make that same forged tape valid only by
    // substituting the fixed-offset input relation with a tautology. A proof
    // valid for that different ProgramTable must fail under the canonical
    // MerkleHash equations.
    auto substituted_table =
        canonical_table;
    auto& substituted =
        substituted_table.programs[
            stage3_poseidon_air::kFixedConstraints];
    cb::Instruction load;
    load.opcode = cb::Opcode::Current;
    load.lhs = input_pin;
    cb::Instruction subtract;
    subtract.opcode = cb::Opcode::Sub;
    subtract.lhs = 0;
    subtract.rhs = 1;
    substituted.instructions = {
        load, load, subtract};
    substituted.declared_degree = 1;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            substituted_table, &why),
        why);
    BOOST_CHECK(
        cb::CommitProgramTableAlgHash(
            substituted_table) !=
        cb::CommitProgramTableAlgHash(
            canonical_table));
    aq::AirConstraintSystem<gf::Fp3>
        substituted_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            substituted_table,
            shard.hash_cs.n_rows,
            substituted_cs, &why),
        why);
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            substituted_cs, forged),
        0U);

    // Split-RAP requires an explicit R0 group. Pin one unchanged internal
    // Poseidon auxiliary solely for this adversarial proof harness; no hash
    // input/output pin is included.
    const uint32_t harness_schedule_column =
        shard.hash_layout.poseidon.X2Col(0);
    canonical_cs.preprocessed_pin_ood = true;
    substituted_cs.preprocessed_pin_ood = true;
    canonical_cs.preprocessed.emplace_back(
        harness_schedule_column,
        forged[harness_schedule_column]);
    substituted_cs.preprocessed =
        canonical_cs.preprocessed;
    const std::vector<uint32_t> preprocessed{
        harness_schedule_column};
    const auto malicious =
        aq::AirQuotientProveRowsSplitRap(
            substituted_cs, forged,
            preprocessed, uint256::ONE);
    BOOST_REQUIRE_MESSAGE(
        malicious.ok, malicious.note);
    BOOST_REQUIRE(
        malicious.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            canonical_cs, malicious.proof,
            preprocessed, uint256::ONE,
            &why));
}

BOOST_AUTO_TEST_CASE(
    merkle_hash_source_address_carry_residual_stays_fail_closed)
{
    const auto input = ActualInput();
    const auto honest =
        OneQueryMerkleShard(input);
    BOOST_REQUIRE(
        !honest.hash_tasks.empty());
    BOOST_REQUIRE(
        !honest.hash_tasks.front()
             .source_addresses.empty());
    auto relabelled = honest;
    ++relabelled.hash_tasks.front()
          .source_addresses.front();

    const auto table =
        BuildMerkleHashProgramTableV1(
            honest.hash_layout);
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table, honest.hash_cs.n_rows,
            cs, &why),
        why);
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            cs, honest.hash_columns),
        0U);
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            cs, relabelled.hash_columns),
        0U);
    // HashTask source addresses are not trace columns yet. This canary
    // intentionally demonstrates why the global row-semantic carry and
    // authority flags must remain false until Decoder is staticized and
    // equality-constrained to these fixed hash rows.
    BOOST_CHECK(
        honest.hash_tasks.front()
            .source_addresses !=
        relabelled.hash_tasks.front()
            .source_addresses);
    BOOST_CHECK(
        cb::CommitProgramTableAlgHash(table) ==
        cb::CommitProgramTableAlgHash(
            BuildMerkleHashProgramTableV1(
                relabelled.hash_layout)));
}

BOOST_AUTO_TEST_CASE(
    merkle_fold_static_bytecode_excludes_tape_and_rejects_offset_substitution)
{
    const auto input = ActualInput();
    const auto shard =
        OneQueryMerkleShard(input);
    const auto canonical_table =
        BuildMerkleFoldProgramTableV1(
            shard.fold_layout);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            canonical_table, &why),
        why);
    BOOST_CHECK_EQUAL(
        canonical_table.programs.size(),
        13U);
    BOOST_CHECK_EQUAL(
        canonical_table.programs.size(),
        shard.fold_cs.constraints.size());
    aq::AirConstraintSystem<gf::Fp3>
        canonical_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            canonical_table,
            shard.fold_cs.n_rows,
            canonical_cs, &why),
        why);
    BOOST_CHECK(
        canonical_cs.preprocessed.empty());
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            canonical_cs,
            shard.fold_columns),
        0U);

    for (uint32_t probe = 0;
         probe < 3; ++probe) {
        std::vector<gf::Fp3> current(
            shard.fold_cs.n_columns);
        std::vector<gf::Fp3> next(
            shard.fold_cs.n_columns);
        for (uint32_t column = 0;
             column < shard.fold_cs.n_columns;
             ++column) {
            current[column] = {
                gf::FromU64(
                    3 + probe * 17 + column),
                gf::FromU64(
                    5 + probe * 19 + 2 * column),
                gf::FromU64(
                    7 + probe * 23 + 3 * column)};
            next[column] = {
                gf::FromU64(
                    11 + probe * 29 + column),
                gf::FromU64(
                    13 + probe * 31 + 2 * column),
                gf::FromU64(
                    17 + probe * 37 + 3 * column)};
        }
        for (uint32_t ordinal = 0;
             ordinal <
                 canonical_table.programs.size();
             ++ordinal) {
            gf::Fp3 interpreted;
            BOOST_REQUIRE_MESSAGE(
                cb::EvaluateProgram(
                    canonical_table.programs[
                        ordinal],
                    current, next,
                    interpreted, &why),
                why);
            const auto native =
                shard.fold_cs.constraints[
                    ordinal].eval(
                        current, next);
            BOOST_CHECK_MESSAGE(
                gf::Eq(interpreted, native),
                "MerkleFold differential mismatch"
                    << " probe=" << probe
                    << " ordinal=" << ordinal);
        }
    }

    uint32_t terminal_row =
        shard.fold_cs.n_rows;
    for (uint32_t row = 0;
         row < shard.fold_cs.n_rows;
         ++row) {
        if (gf::Eq(
                shard.fold_columns[
                    shard.fold_layout.terminal][row],
                gf::Fp3::One())) {
            terminal_row = row;
            break;
        }
    }
    BOOST_REQUIRE_LT(
        terminal_row,
        shard.fold_cs.n_rows);
    auto forged = shard.fold_columns;
    forged[
        shard.fold_layout.final_value][terminal_row] =
        gf::Add(
            forged[
                shard.fold_layout.final_value][
                    terminal_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        air_recurse::CountWitnessViolationsOnH(
            canonical_cs, forged),
        0U);

    // Substitute the terminal claim's fixed source offset with the folded
    // cell itself. The resulting equation terminal*(folded-folded)=0 accepts
    // the forged value, but its different ProgramTable root cannot verify
    // under the canonical fixed-offset relation.
    auto substituted_table =
        canonical_table;
    auto& terminal =
        substituted_table.programs.back();
    cb::Instruction terminal_load;
    terminal_load.opcode =
        cb::Opcode::Current;
    terminal_load.lhs =
        shard.fold_layout.terminal;
    cb::Instruction folded_load;
    folded_load.opcode =
        cb::Opcode::Current;
    folded_load.lhs =
        shard.fold_layout.folded;
    cb::Instruction subtract;
    subtract.opcode = cb::Opcode::Sub;
    subtract.lhs = 1;
    subtract.rhs = 2;
    cb::Instruction multiply;
    multiply.opcode = cb::Opcode::Mul;
    multiply.lhs = 0;
    multiply.rhs = 3;
    terminal.instructions = {
        terminal_load,
        folded_load,
        folded_load,
        subtract,
        multiply,
    };
    terminal.declared_degree = 2;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            substituted_table, &why),
        why);
    BOOST_CHECK(
        cb::CommitProgramTableAlgHash(
            substituted_table) !=
        cb::CommitProgramTableAlgHash(
            canonical_table));
    aq::AirConstraintSystem<gf::Fp3>
        substituted_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            substituted_table,
            shard.fold_cs.n_rows,
            substituted_cs, &why),
        why);
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            substituted_cs, forged),
        0U);
    const uint32_t harness_schedule_column =
        shard.fold_layout.x;
    canonical_cs.preprocessed_pin_ood = true;
    canonical_cs.preprocessed.emplace_back(
        harness_schedule_column,
        forged[harness_schedule_column]);
    substituted_cs.preprocessed_pin_ood = true;
    substituted_cs.preprocessed =
        canonical_cs.preprocessed;
    const std::vector<uint32_t> preprocessed{
        harness_schedule_column};
    const auto malicious =
        aq::AirQuotientProveRowsSplitRap(
            substituted_cs, forged,
            preprocessed, uint256::ONE);
    BOOST_REQUIRE_MESSAGE(
        malicious.ok, malicious.note);
    BOOST_REQUIRE(
        malicious.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            canonical_cs, malicious.proof,
            preprocessed, uint256::ONE,
            &why));
}

BOOST_AUTO_TEST_CASE(
    merkle_fold_disconnected_transcript_and_x_plus_p_stay_fail_closed)
{
    const auto input = ActualInput();
    const auto shard =
        OneQueryMerkleShard(input);
    const auto table =
        BuildMerkleFoldProgramTableV1(
            shard.fold_layout);
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table, shard.fold_cs.n_rows,
            cs, &why),
        why);

    // A self-consistent all-terminal fold table with arbitrary betas proves
    // the local equations while carrying no openings, transcript challenge,
    // or final value. This is the concrete attack the later Decoder/FS carry
    // must rule out.
    std::vector<std::vector<gf::Fp3>> disconnected(
        shard.fold_cs.n_columns,
        std::vector<gf::Fp3>(
            shard.fold_cs.n_rows,
            gf::Fp3::Zero()));
    for (uint32_t row = 0;
         row < shard.fold_cs.n_rows;
         ++row) {
        disconnected[
            shard.fold_layout.beta][row] =
            gf::Fp3::FromFp(100 + row);
        disconnected[
            shard.fold_layout.x][row] =
            gf::Fp3::One();
        disconnected[
            shard.fold_layout.odd_index][row] =
            gf::Fp3::One();
        disconnected[
            shard.fold_layout.half][row] =
            gf::Fp3::One();
        disconnected[
            shard.fold_layout.terminal][row] =
            gf::Fp3::One();
    }
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            cs, disconnected),
        0U);
    bool differs_from_honest = false;
    for (uint32_t column = 0;
         column < shard.fold_cs.n_columns &&
         !differs_from_honest;
         ++column) {
        for (uint32_t row = 0;
             row < shard.fold_cs.n_rows;
             ++row) {
            if (!gf::Eq(
                    disconnected[column][row],
                    shard.fold_columns[column][row])) {
                differs_from_honest = true;
                break;
            }
        }
    }
    BOOST_CHECK(
        differs_from_honest);

    // A field cell cannot distinguish x from x+p. The production remedy is
    // the canonical u32 decoder carry, not an invalid low-bit predicate over
    // Fp3. Keep the carry flag false until that exact join executes.
    const uint64_t small = 7;
    BOOST_CHECK(
        gf::Eq(
            gf::Fp3::FromFp(
                gf::FromU64(small)),
            gf::Fp3::FromFp(
                gf::FromU64(
                    gf::kP + small))));
}

BOOST_AUTO_TEST_CASE(
    deep_vm_bytecode_matches_all_native_constraints_and_rejects_substitution)
{
    const auto input = ActualInput();
    const auto native =
        OneQueryDeepVm(input);
    const auto table =
        BuildDeepVmProgramTableV1(
            native.layout);
    const auto phase =
        BuildDeepVmCanonicalPhaseV1(
            native,
            input.child_program,
            input.expected_child_program_root,
            {0, 0, 1});
    const auto challenge =
        phase.challenge;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        phase.valid, phase.note);
    BOOST_CHECK(
        phase.program_and_range_bound);
    BOOST_CHECK(
        phase.constant_schedule_owned);
    BOOST_CHECK(
        phase.register_logup_complete);
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            table, &why),
        why);
    BOOST_CHECK_EQUAL(
        table.programs.size(),
        kDeepVmCanonicalConstraintsV1);
    BOOST_CHECK_EQUAL(
        kDeepVmNativeConstraintsV1,
        native.cs.constraints.size());
    BOOST_CHECK_EQUAL(
        table.current_width,
        native.layout.n_columns +
            kDeepVmExtensionColumnsV1);
    BOOST_CHECK_EQUAL(
        table.challenge_width,
        kDeepVmChallengeColumnsV1);
    BOOST_CHECK(
        cb::ProgramTableIsChallengeIndependent(
            table));
    for (const auto& program :
         table.programs) {
        BOOST_CHECK_LE(
            program.declared_degree, 2U);
    }
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            phase.cs,
            phase.columns),
        0U);
    for (uint32_t probe = 0;
         probe < 3; ++probe) {
        std::vector<gf::Fp3> current(
            table.current_width);
        std::vector<gf::Fp3> next(
            table.current_width);
        for (uint32_t column = 0;
             column <
                 table.current_width;
             ++column) {
            current[column] = {
                gf::FromU64(
                    3 + probe * 17 + column),
                gf::FromU64(
                    5 + probe * 19 +
                        2 * column),
                gf::FromU64(
                    7 + probe * 23 +
                        3 * column)};
            next[column] = {
                gf::FromU64(
                    11 + probe * 29 + column),
                gf::FromU64(
                    13 + probe * 31 +
                        2 * column),
                gf::FromU64(
                    17 + probe * 37 +
                        3 * column)};
        }
        for (uint32_t ordinal = 0;
             ordinal <
                 kDeepVmNativeConstraintsV1;
             ++ordinal) {
            gf::Fp3 interpreted;
            BOOST_REQUIRE_MESSAGE(
                cb::EvaluateProgram(
                    table.programs[ordinal],
                    current, next,
                    challenge,
                    interpreted, &why),
                why);
            const auto expected =
                native.cs.constraints[
                    ordinal].eval(
                        current, next);
            BOOST_CHECK_MESSAGE(
                gf::Eq(
                    interpreted, expected),
                "DeepVM differential mismatch"
                    << " probe=" << probe
                    << " ordinal=" << ordinal);
        }
    }

    // The old 284 equations accepted a self-consistent relabel of a constant
    // operand/result because neither cell was tied to ProgramTable bytes.
    // The canonical phase rejects exactly that witness through the new
    // verifier-owned constant schedule.
    uint32_t constant_row =
        std::numeric_limits<uint32_t>::max();
    for (uint32_t row = 0;
         row < native.real_rows; ++row) {
        if (gf::Eq(
                native.columns[
                    native.layout.op_constant][row],
                gf::Fp3::One()) &&
            gf::IsZero(
                native.columns[
                    native.layout.program_end][row])) {
            constant_row = row;
            break;
        }
    }
    BOOST_REQUIRE_NE(
        constant_row,
        std::numeric_limits<uint32_t>::max());
    auto constant_native_attack =
        native.columns;
    const auto delta = gf::Fp3::One();
    const auto refresh_vm_row =
        [&native](
            std::vector<std::vector<gf::Fp3>>&
                columns,
            uint32_t row) {
            const auto& l = native.layout;
            columns[l.mul_product][row] =
                gf::Mul(
                    columns[l.operand_lhs][row],
                    columns[l.operand_rhs][row]);
            columns[l.selected_result][row] =
                gf::Mul(
                    columns[l.selector][row],
                    columns[
                        l.instruction_result][row]);
            columns[l.lambda_selected][row] =
                gf::Mul(
                    columns[l.lambda_power][row],
                    columns[l.selected_result][row]);
            columns[l.program_contribution][row] =
                gf::Mul(
                    columns[l.program_end][row],
                    columns[l.lambda_selected][row]);
            columns[l.composition_after][row] =
                gf::Add(
                    columns[
                        l.composition_before][row],
                    columns[
                        l.program_contribution][row]);
        };
    constant_native_attack[
        native.layout.operand_lhs][constant_row] =
        gf::Add(
            constant_native_attack[
                native.layout.operand_lhs][
                constant_row],
            delta);
    constant_native_attack[
        native.layout.instruction_result][
        constant_row] =
        gf::Add(
            constant_native_attack[
                native.layout.instruction_result][
                constant_row],
            delta);
    refresh_vm_row(
        constant_native_attack,
        constant_row);
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            native.cs,
            constant_native_attack),
        0U);
    auto constant_canonical_attack =
        phase.columns;
    constant_canonical_attack[
        native.layout.operand_lhs][constant_row] =
        constant_native_attack[
            native.layout.operand_lhs][
                constant_row];
    constant_canonical_attack[
        native.layout.instruction_result][
        constant_row] =
        constant_native_attack[
            native.layout.instruction_result][
                constant_row];
    for (uint32_t column :
         {native.layout.mul_product,
          native.layout.selected_result,
          native.layout.lambda_selected,
          native.layout.program_contribution,
          native.layout.composition_after}) {
        constant_canonical_attack[column][
            constant_row] =
            constant_native_attack[column][
                constant_row];
    }
    BOOST_CHECK_GT(
        air_recurse::CountWitnessViolationsOnH(
            phase.cs,
            constant_canonical_attack),
        0U);

    // Likewise, an internal binary operand and its row-local result could be
    // changed together under the native VM callbacks. Because later reads
    // were free witnesses, this was a genuine SSA-copy attack. The indexed
    // register multiset now rejects it.
    uint32_t binary_row =
        std::numeric_limits<uint32_t>::max();
    for (uint32_t row = 0;
         row < native.real_rows; ++row) {
        const bool binary =
            gf::Eq(
                native.columns[
                    native.layout.op_add][row],
                gf::Fp3::One()) ||
            gf::Eq(
                native.columns[
                    native.layout.op_sub][row],
                gf::Fp3::One());
        if (binary &&
            gf::IsZero(
                native.columns[
                    native.layout.program_end][row])) {
            binary_row = row;
            break;
        }
    }
    BOOST_REQUIRE_NE(
        binary_row,
        std::numeric_limits<uint32_t>::max());
    auto register_native_attack =
        native.columns;
    register_native_attack[
        native.layout.operand_lhs][binary_row] =
        gf::Add(
            register_native_attack[
                native.layout.operand_lhs][
                binary_row],
            delta);
    const bool is_add =
        gf::Eq(
            register_native_attack[
                native.layout.op_add][binary_row],
            gf::Fp3::One());
    register_native_attack[
        native.layout.instruction_result][
        binary_row] =
        is_add
        ? gf::Add(
              register_native_attack[
                  native.layout.operand_lhs][
                  binary_row],
              register_native_attack[
                  native.layout.operand_rhs][
                  binary_row])
        : gf::Sub(
              register_native_attack[
                  native.layout.operand_lhs][
                  binary_row],
              register_native_attack[
                  native.layout.operand_rhs][
                  binary_row]);
    refresh_vm_row(
        register_native_attack,
        binary_row);
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            native.cs,
            register_native_attack),
        0U);
    auto register_canonical_attack =
        phase.columns;
    register_canonical_attack[
        native.layout.operand_lhs][binary_row] =
        register_native_attack[
            native.layout.operand_lhs][
                binary_row];
    register_canonical_attack[
        native.layout.instruction_result][
        binary_row] =
        register_native_attack[
            native.layout.instruction_result][
                binary_row];
    register_canonical_attack[
        native.layout.mul_product][binary_row] =
        register_native_attack[
            native.layout.mul_product][
                binary_row];
    register_canonical_attack[
        native.layout.selected_result][
        binary_row] =
        register_native_attack[
            native.layout.selected_result][
                binary_row];
    register_canonical_attack[
        native.layout.lambda_selected][
        binary_row] =
        register_native_attack[
            native.layout.lambda_selected][
                binary_row];
    register_canonical_attack[
        native.layout.program_contribution][
        binary_row] =
        register_native_attack[
            native.layout.program_contribution][
                binary_row];
    register_canonical_attack[
        native.layout.composition_after][
        binary_row] =
        register_native_attack[
            native.layout.composition_after][
                binary_row];
    BOOST_CHECK_GT(
        air_recurse::CountWitnessViolationsOnH(
            phase.cs,
            register_canonical_attack),
        0U);
    auto stale_dvr1_attack =
        register_canonical_attack;
    BOOST_CHECK(
        !FillDeepVmSsaAuxV1(
            native.layout,
            challenge,
            stale_dvr1_attack));
    BOOST_CHECK_GT(
        air_recurse::CountWitnessViolationsOnH(
            phase.cs,
            stale_dvr1_attack),
        0U);

    auto wrong_root =
        input.expected_child_program_root;
    wrong_root[0] ^= 1U;
    BOOST_CHECK(
        !BuildDeepVmCanonicalPhaseV1(
             native,
             input.child_program,
             wrong_root,
             {0, 0, 1}).valid);
    BOOST_CHECK(
        !BuildDeepVmCanonicalPhaseV1(
             native,
             input.child_program,
             input.expected_child_program_root,
             {0, 1, 1}).valid);
    auto substituted_operand_root = native;
    substituted_operand_root
        .preprocessed_row_group_root.data()[0] ^=
        1U;
    BOOST_CHECK(
        !BuildDeepVmCanonicalPhaseV1(
             substituted_operand_root,
             input.child_program,
             input.expected_child_program_root,
             {0, 0, 1}).valid);

    // Proof-level version of the SSA attack: a malicious ProgramTable that
    // replaces all 37 ownership/LogUp constraints with tautologies can prove
    // the forged old-native witness, but the canonical verifier rejects that
    // proof under the committed 321-program relation.
    auto weakened_table = table;
    for (uint32_t ordinal =
             kDeepVmNativeConstraintsV1;
         ordinal <
             weakened_table.programs.size();
         ++ordinal) {
        auto& program =
            weakened_table.programs[ordinal];
        program.instructions = {
            Load(
                cb::Opcode::Current,
                native.layout.active),
            Load(
                cb::Opcode::Current,
                native.layout.active),
            Binary(cb::Opcode::Sub, 0, 1),
        };
        program.declared_degree = 1;
    }
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            weakened_table, &why),
        why);
    BOOST_CHECK(
        cb::CommitProgramTableAlgHash(
            weakened_table) !=
        cb::CommitProgramTableAlgHash(table));
    aq::AirConstraintSystem<gf::Fp3>
        weakened_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            weakened_table,
            phase.cs.n_rows,
            challenge,
            weakened_cs, &why),
        why);
    weakened_cs.preprocessed =
        phase.cs.preprocessed;
    weakened_cs.preprocessed_pin_ood = true;
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            weakened_cs,
            register_canonical_attack),
        0U);
    const auto register_attack_proof =
        aq::AirQuotientProveRowsSplitRap(
            weakened_cs,
            register_canonical_attack,
            phase.statement_manifest_columns,
            uint256::ONE);
    BOOST_REQUIRE_MESSAGE(
        register_attack_proof.ok,
        register_attack_proof.note);
    BOOST_REQUIRE(
        register_attack_proof.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            phase.cs,
            register_attack_proof.proof,
            phase.statement_manifest_columns,
            uint256::ONE, &why));

    // A small all-padding trace satisfies every fixed DeepVM relation. The
    // non-max high-limb inverse is the only nonzero canonicality witness.
    const auto layout =
        dvm::CanonicalLayoutV1();
    const auto small_table =
        BuildDeepVmProgramTableV1(layout);
    aq::AirConstraintSystem<gf::Fp3>
        small_canonical_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            small_table, 8,
            challenge,
            small_canonical_cs, &why),
        why);
    std::vector<std::vector<gf::Fp3>>
        columns(
            small_table.current_width,
            std::vector<gf::Fp3>(
                8, gf::Fp3::Zero()));
    const auto max_u32 =
        gf::Fp3::FromFp(
            std::numeric_limits<
                uint32_t>::max());
    const auto zero_delta_inverse =
        gf::Inv(gf::Sub(
            gf::Fp3::Zero(),
            max_u32));
    for (uint32_t coordinate = 0;
         coordinate <
             dvm::kFp3CoordinatesV1;
         ++coordinate) {
        for (uint32_t row = 0;
             row < 8; ++row) {
            columns[
                layout
                    .quotient_high_delta_inverse[
                        coordinate]][row] =
                zero_delta_inverse;
        }
    }
    FillDeepVmPaddingSsaV1(
        layout, columns);
    small_canonical_cs.preprocessed_pin_ood =
        true;
    small_canonical_cs.preprocessed.emplace_back(
        layout.active,
        columns[layout.active]);
    const std::vector<uint32_t> preprocessed{
        layout.active};
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            small_canonical_cs, columns),
        0U);

    auto forged = columns;
    forged[layout.quotient_tape_accept][0] =
        gf::Fp3::One();
    BOOST_CHECK_GT(
        air_recurse::CountWitnessViolationsOnH(
            small_canonical_cs, forged),
        0U);
    auto substituted_table =
        small_table;
    auto& acceptance =
        substituted_table.programs[
            kDeepVmNativeConstraintsV1 - 1];
    acceptance.instructions = {
        Load(
            cb::Opcode::Current,
            layout.quotient_tape_accept),
        Load(
            cb::Opcode::Current,
            layout.quotient_tape_accept),
        Binary(cb::Opcode::Sub, 0, 1),
    };
    acceptance.declared_degree = 1;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            substituted_table, &why),
        why);
    BOOST_CHECK(
        cb::CommitProgramTableAlgHash(
            substituted_table) !=
        cb::CommitProgramTableAlgHash(
            small_table));
    aq::AirConstraintSystem<gf::Fp3>
        substituted_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            substituted_table, 8,
            challenge,
            substituted_cs, &why),
        why);
    substituted_cs.preprocessed_pin_ood =
        true;
    substituted_cs.preprocessed =
        small_canonical_cs.preprocessed;
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            substituted_cs, forged),
        0U);
    const auto malicious =
        aq::AirQuotientProveRowsSplitRap(
            substituted_cs, forged,
            preprocessed, uint256::ONE);
    BOOST_REQUIRE_MESSAGE(
        malicious.ok, malicious.note);
    BOOST_REQUIRE(
        malicious.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            small_canonical_cs,
            malicious.proof,
            preprocessed,
            uint256::ONE, &why));

    // Challenges are verifier-owned post-R0 values. A proof generated for a
    // distinct valid lane vector cannot be transplanted under the canonical
    // Fiat-Shamir replay, while both executions retain the same statement
    // manifest.
    auto alternate_challenge = challenge;
    alternate_challenge[0] =
        gf::Add(
            alternate_challenge[0],
            gf::Fp3::One());
    if (gf::Eq(
            alternate_challenge[0],
            alternate_challenge[1]) ||
        gf::IsZero(
            alternate_challenge[0])) {
        alternate_challenge[0] =
            gf::Add(
                alternate_challenge[0],
                gf::FromU64_3(2));
    }
    auto alternate_columns =
        phase.columns;
    BOOST_REQUIRE(
        FillDeepVmSsaAuxV1(
            native.layout,
            alternate_challenge,
            alternate_columns));
    aq::AirConstraintSystem<gf::Fp3>
        alternate_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table,
            phase.cs.n_rows,
            alternate_challenge,
            alternate_cs, &why),
        why);
    alternate_cs.preprocessed =
        phase.cs.preprocessed;
    alternate_cs.preprocessed_pin_ood =
        true;
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            alternate_cs,
            alternate_columns),
        0U);
    const auto alternate_proof =
        aq::AirQuotientProveRowsSplitRap(
            alternate_cs,
            alternate_columns,
            phase.statement_manifest_columns,
            uint256::ONE);
    BOOST_REQUIRE_MESSAGE(
        alternate_proof.ok,
        alternate_proof.note);
    BOOST_REQUIRE(
        alternate_proof.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            phase.cs,
            alternate_proof.proof,
            phase.statement_manifest_columns,
            uint256::ONE, &why));

    // source_address is ordinary and intentionally not consumed by any local
    // DeepVM relation. Its equality to Decoder/ABI cells is a later CTL
    // obligation, so the global carry/authority flags must remain false.
    auto relabelled = columns;
    relabelled[layout.source_address][0] =
        gf::Fp3::One();
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            small_canonical_cs,
            relabelled),
        0U);
}

BOOST_AUTO_TEST_CASE(
    decoder_horner_bytecode_matches_native_and_rejects_offset_substitution)
{
    const auto input = ActualInput();
    const auto shard =
        OneQueryMerkleShard(input);
    const auto decoder =
        OneQueryDecoder(input, shard);
    const auto challenge =
        DecoderChallengeVector(decoder);
    const auto canonical_table =
        BuildDecoderProgramTableV1(
            decoder.layout);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            canonical_table, &why),
        why);
    BOOST_CHECK(
        cb::ProgramTableIsChallengeIndependent(
            canonical_table));
    BOOST_CHECK_EQUAL(
        canonical_table.challenge_width,
        kDecoderChallengeColumnsV1);
    BOOST_CHECK_EQUAL(
        canonical_table.programs.size(),
        30U);
    BOOST_CHECK_EQUAL(
        canonical_table.current_width,
        decoder.layout.n_columns +
            kDecoderHornerAuxColumnsV1);
    for (const auto& program :
         canonical_table.programs) {
        BOOST_CHECK_LE(
            program.declared_degree, 2U);
    }

    aq::AirConstraintSystem<gf::Fp3>
        canonical_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            canonical_table,
            decoder.cs.n_rows,
            challenge,
            canonical_cs, &why),
        why);
    std::vector<std::vector<gf::Fp3>>
        static_columns(
            canonical_table.current_width,
            std::vector<gf::Fp3>(
                decoder.cs.n_rows,
                gf::Fp3::Zero()));
    for (uint32_t column = 0;
         column < decoder.layout.n_columns;
         ++column) {
        static_columns[column] =
            decoder.columns[column];
    }
    for (uint32_t row = 0;
         row < decoder.cs.n_rows;
         ++row) {
        std::vector<gf::Fp3> values(
            canonical_table.current_width);
        for (uint32_t column = 0;
             column <
                 canonical_table.current_width;
             ++column) {
            values[column] =
                static_columns[column][row];
        }
        FillDecoderHornerRow(
            decoder.layout,
            challenge, values);
        for (uint32_t column =
                 decoder.layout.n_columns;
             column <
                 canonical_table.current_width;
             ++column) {
            static_columns[column][row] =
                values[column];
        }
    }
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            canonical_cs,
            static_columns),
        0U);

    // Differentially compare the ten original semantic equations per lane
    // against the degree-reduced table on arbitrary Fp3 rows. The added
    // Horner equations are checked independently to vanish after their
    // deterministic auxiliary construction.
    for (uint32_t probe = 0;
         probe < 3; ++probe) {
        std::vector<gf::Fp3> current(
            canonical_table.current_width);
        std::vector<gf::Fp3> next(
            canonical_table.current_width);
        for (uint32_t column = 0;
             column <
                 decoder.layout.n_columns;
             ++column) {
            current[column] = {
                gf::FromU64(
                    3 + probe * 17 + column),
                gf::FromU64(
                    5 + probe * 19 +
                        2 * column),
                gf::FromU64(
                    7 + probe * 23 +
                        3 * column)};
            next[column] = {
                gf::FromU64(
                    11 + probe * 29 + column),
                gf::FromU64(
                    13 + probe * 31 +
                        2 * column),
                gf::FromU64(
                    17 + probe * 37 +
                        3 * column)};
        }
        FillDecoderHornerRow(
            decoder.layout,
            challenge, current);
        FillDecoderHornerRow(
            decoder.layout,
            challenge, next);
        for (uint32_t ordinal = 0;
             ordinal < 4; ++ordinal) {
            gf::Fp3 interpreted;
            BOOST_REQUIRE_MESSAGE(
                cb::EvaluateProgram(
                    canonical_table.programs[
                        ordinal],
                    current, next,
                    challenge,
                    interpreted, &why),
                why);
            BOOST_CHECK(
                gf::Eq(
                    interpreted,
                    decoder.cs.constraints[
                        ordinal].eval(
                            current, next)));
        }
        for (uint32_t lane = 0;
             lane <
                 dj::kDecoderJoinBusLanesV1;
             ++lane) {
            const uint32_t canonical_base =
                4 + 13 * lane;
            const uint32_t native_base =
                4 + 5 * lane;
            for (uint32_t horner = 0;
                 horner < 4; ++horner) {
                gf::Fp3 interpreted;
                BOOST_REQUIRE_MESSAGE(
                    cb::EvaluateProgram(
                        canonical_table.programs[
                            canonical_base +
                                horner],
                        current, next,
                        challenge,
                        interpreted, &why),
                    why);
                BOOST_CHECK(
                    gf::IsZero(interpreted));
                BOOST_REQUIRE_MESSAGE(
                    cb::EvaluateProgram(
                        canonical_table.programs[
                            canonical_base + 5 +
                                horner],
                        current, next,
                        challenge,
                        interpreted, &why),
                    why);
                BOOST_CHECK(
                    gf::IsZero(interpreted));
            }
            const std::array<
                std::pair<uint32_t, uint32_t>,
                5>
                parity{{
                    {canonical_base + 4,
                     native_base},
                    {canonical_base + 9,
                     native_base + 1},
                    {canonical_base + 10,
                     native_base + 2},
                    {canonical_base + 11,
                     native_base + 3},
                    {canonical_base + 12,
                     native_base + 4},
                }};
            for (const auto& [
                     bytecode_ordinal,
                     native_ordinal] :
                 parity) {
                gf::Fp3 interpreted;
                BOOST_REQUIRE_MESSAGE(
                    cb::EvaluateProgram(
                        canonical_table.programs[
                            bytecode_ordinal],
                        current, next,
                        challenge,
                        interpreted, &why),
                    why);
                BOOST_CHECK_MESSAGE(
                    gf::Eq(
                        interpreted,
                        decoder.cs.constraints[
                            native_ordinal].eval(
                                current, next)),
                    "Decoder differential mismatch"
                        << " probe=" << probe
                        << " bytecode="
                        << bytecode_ordinal
                        << " native="
                        << native_ordinal);
            }
        }
    }

    // Fixed-offset proof attack: changing source_value can be made valid only
    // by substituting both source h1 programs to read consumer_claim. A proof
    // for that different table must be rejected by the canonical verifier.
    const auto layout =
        dj::CanonicalLayoutV1();
    const std::vector<gf::Fp3>
        synthetic_challenge{
            gf::Fp3::FromFp(11),
            gf::Fp3::FromFp(13),
            gf::Fp3::FromFp(17),
            gf::Fp3::FromFp(19),
        };
    const auto small_table =
        BuildDecoderProgramTableV1(layout);
    aq::AirConstraintSystem<gf::Fp3>
        small_canonical_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            small_table, 8,
            synthetic_challenge,
            small_canonical_cs, &why),
        why);
    auto forged =
        BuildSyntheticDecoderTrace(
            layout, synthetic_challenge);
    InstallDecoderManifest(
        layout, forged,
        small_canonical_cs);
    forged[layout.source_value][0] =
        gf::Add(
            forged[layout.source_value][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        air_recurse::CountWitnessViolationsOnH(
            small_canonical_cs, forged),
        0U);

    auto substituted_table =
        small_table;
    for (uint32_t lane = 0;
         lane < dj::kDecoderJoinBusLanesV1;
         ++lane) {
        auto& program =
            substituted_table.programs[
                4 + 13 * lane];
        program.instructions = {
            Load(
                cb::Opcode::Current,
                DecoderAuxColumn(
                    layout, lane, 0, 0)),
            Load(
                cb::Opcode::Current,
                layout.source_address),
            Load(
                cb::Opcode::Challenge,
                lane),
            Load(
                cb::Opcode::Current,
                layout.consumer_claim),
            Binary(cb::Opcode::Mul, 2, 3),
            Binary(cb::Opcode::Add, 1, 4),
            Binary(cb::Opcode::Sub, 0, 5),
        };
        program.declared_degree = 2;
    }
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            substituted_table, &why),
        why);
    BOOST_CHECK(
        cb::CommitProgramTableAlgHash(
            substituted_table) !=
        cb::CommitProgramTableAlgHash(
            small_table));
    aq::AirConstraintSystem<gf::Fp3>
        substituted_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            substituted_table, 8,
            synthetic_challenge,
            substituted_cs, &why),
        why);
    InstallDecoderManifest(
        layout, forged,
        substituted_cs);
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            substituted_cs, forged),
        0U);
    const auto manifest =
        DecoderManifestColumns(layout);
    const auto malicious =
        aq::AirQuotientProveRowsSplitRap(
            substituted_cs, forged,
            manifest, uint256::ONE);
    BOOST_REQUIRE_MESSAGE(
        malicious.ok, malicious.note);
    BOOST_REQUIRE(
        malicious.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            small_canonical_cs,
            malicious.proof,
            manifest, uint256::ONE,
            &why));
}

BOOST_AUTO_TEST_CASE(
    decoder_challenge_and_child_root_carries_stay_fail_closed)
{
    const auto layout =
        dj::CanonicalLayoutV1();
    const auto table =
        BuildDecoderProgramTableV1(layout);
    const std::vector<gf::Fp3> challenge{
        gf::Fp3::FromFp(11),
        gf::Fp3::FromFp(13),
        gf::Fp3::FromFp(17),
        gf::Fp3::FromFp(19),
    };
    auto columns =
        BuildSyntheticDecoderTrace(
            layout, challenge);
    columns[layout.root_active][0] =
        gf::Fp3::One();
    columns[layout.root_kind][0] =
        gf::Fp3::FromFp(2);
    columns[layout.root_index][0] =
        gf::Fp3::FromFp(3);
    columns[layout.root_word][0] =
        gf::Fp3::FromFp(4);
    columns[layout.root_value][0] =
        gf::Fp3::FromFp(0x1234);

    aq::AirConstraintSystem<gf::Fp3>
        canonical_cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table, 8, challenge,
            canonical_cs, &why),
        why);
    InstallDecoderManifest(
        layout, columns, canonical_cs);
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            canonical_cs, columns),
        0U);

    // Child root values are now ordinary rather than disguised R0, but no
    // local Decoder equation consumes them. This concrete attack keeps the
    // child-root carry and recursive authority false.
    auto wrong_root = columns;
    wrong_root[layout.root_value][0] =
        gf::Add(
            wrong_root[layout.root_value][0],
            gf::Fp3::One());
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            canonical_cs, wrong_root),
        0U);

    // The ProgramTable is independent of the challenge value. A fixed tape
    // fails under a different verifier challenge, and a freshly recomputed
    // alternate tape can prove only under that alternate challenge. Once the
    // later transcript carry supplies the canonical challenge, transplanting
    // the proof is rejected at proof level.
    auto alternate_challenge =
        challenge;
    alternate_challenge[0] =
        gf::Add(
            alternate_challenge[0],
            gf::Fp3::One());
    aq::AirConstraintSystem<gf::Fp3>
        alternate_cs;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table, 8,
            alternate_challenge,
            alternate_cs, &why),
        why);
    InstallDecoderManifest(
        layout, columns, alternate_cs);
    BOOST_CHECK_GT(
        air_recurse::CountWitnessViolationsOnH(
            alternate_cs, columns),
        0U);

    auto alternate_columns =
        BuildSyntheticDecoderTrace(
            layout, alternate_challenge);
    alternate_columns[layout.root_active][0] =
        columns[layout.root_active][0];
    alternate_columns[layout.root_kind][0] =
        columns[layout.root_kind][0];
    alternate_columns[layout.root_index][0] =
        columns[layout.root_index][0];
    alternate_columns[layout.root_word][0] =
        columns[layout.root_word][0];
    alternate_columns[layout.root_value][0] =
        columns[layout.root_value][0];
    alternate_cs.preprocessed.clear();
    InstallDecoderManifest(
        layout, alternate_columns,
        alternate_cs);
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(
            alternate_cs,
            alternate_columns),
        0U);
    const auto manifest =
        DecoderManifestColumns(layout);
    const auto alternate_proof =
        aq::AirQuotientProveRowsSplitRap(
            alternate_cs,
            alternate_columns,
            manifest, uint256::ONE);
    BOOST_REQUIRE_MESSAGE(
        alternate_proof.ok,
        alternate_proof.note);
    BOOST_REQUIRE(
        alternate_proof.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            canonical_cs,
            alternate_proof.proof,
            manifest, uint256::ONE,
            &why));
}

BOOST_AUTO_TEST_CASE(
    exact_q96_vertical_union_closes_degree_and_lde_but_not_ownership)
{
    const auto input = ActualInput();
    const rv::QueryRangeV1 range{
        0, 0, kQ96QueriesV1};
    const auto product =
        BuildProductV1(input, range);
    BOOST_CHECK(!product.valid_foundation);
    BOOST_CHECK(product.exact_q96_range);
    BOOST_CHECK(product.trace_cap_fits);
    BOOST_CHECK(product.lde_cap_fits);
    BOOST_CHECK(product.quotient_cap_audit_complete);
    BOOST_CHECK(!product.cs_independent_of_child_witness);
    BOOST_CHECK(
        !product.verifier_input_excludes_child_proof);
    BOOST_CHECK(
        !product.direct_cross_phase_cell_carries_complete);
    BOOST_CHECK(!product.recursive_authority_ready);
    BOOST_CHECK(product.acceptance_ordinary_witness);
    BOOST_CHECK(product.acceptance_unique);
    BOOST_CHECK(
        product.whole_verifier_acceptance_constrained);
    BOOST_CHECK(
        product
            .acceptance_constraints_canonical_bytecode);
    BOOST_CHECK(
        product
            .acceptance_program_root_recomputed);
    BOOST_CHECK_EQUAL(
        product.acceptance_program_constraints,
        2U);
    BOOST_CHECK(
        product
            .scheduler_constraints_canonical_bytecode);
    BOOST_CHECK(
        product
            .scheduler_program_root_recomputed);
    BOOST_CHECK_EQUAL(
        product.scheduler_program_constraints,
        2 + 4 * kPhasesV1);
    BOOST_CHECK(
        product
            .parent_join_constraints_canonical_bytecode);
    BOOST_CHECK(
        product
            .parent_join_program_root_recomputed);
    BOOST_CHECK_EQUAL(
        product.parent_join_program_constraints,
        np::kExpectedProgramsV1);
    BOOST_CHECK_EQUAL(
        product
            .phase_constraint_systems_canonical_bytecode,
        5U);
    BOOST_CHECK_EQUAL(
        product
            .phase_r0_tables_statement_manifest_only,
        5U);
    BOOST_CHECK(
        product
            .parent_join_r0_statement_manifest_only);
    BOOST_CHECK(
        product
            .parent_join_cs_independent_of_child_witness);
    BOOST_CHECK(
        product.parent_join_proof_tape_cells_ordinary);
    BOOST_CHECK(
        product.parent_join_proof_tape_fixed_offsets);
    BOOST_CHECK(
        product.parent_join_digest_claims_poseidon_bound);
    BOOST_CHECK(
        product.parent_join_statement_root_r0_bound);
    BOOST_CHECK(
        product.parent_join_statement_manifest_r0_root ==
        input.expected_child_statement_root);
    BOOST_CHECK(
        product
            .merkle_hash_constraints_canonical_bytecode);
    BOOST_CHECK(
        product
            .merkle_hash_program_root_recomputed);
    BOOST_CHECK_EQUAL(
        product.merkle_hash_program_constraints,
        stage3_poseidon_air::kFixedConstraints +
            alg_hash::kAlgHashT +
            alg_hash::kAlgHashDigestLen);
    BOOST_CHECK_EQUAL(
        product
            .merkle_hash_statement_manifest_r0_columns,
        0U);
    BOOST_CHECK_EQUAL(
        product.merkle_hash_proof_tape_cells,
        alg_hash::kAlgHashT +
            alg_hash::kAlgHashDigestLen);
    BOOST_CHECK(
        product
            .merkle_hash_proof_tape_cells_ordinary);
    BOOST_CHECK(
        product
            .merkle_hash_proof_tape_fixed_lane_offsets);
    BOOST_CHECK(
        product.merkle_hash_io_poseidon_bound);
    BOOST_CHECK(
        product
            .merkle_hash_r0_statement_manifest_only);
    BOOST_CHECK(
        product
            .merkle_hash_cs_independent_of_child_witness);
    BOOST_CHECK(
        !product
             .merkle_hash_row_semantic_carry_complete);
    BOOST_CHECK(
        product
            .merkle_fold_constraints_canonical_bytecode);
    BOOST_CHECK(
        product
            .merkle_fold_program_root_recomputed);
    BOOST_CHECK_EQUAL(
        product.merkle_fold_program_constraints,
        13U);
    BOOST_CHECK_EQUAL(
        product
            .merkle_fold_statement_manifest_r0_columns,
        0U);
    BOOST_CHECK_EQUAL(
        product.merkle_fold_proof_tape_cells,
        16U);
    BOOST_CHECK(
        product
            .merkle_fold_proof_tape_cells_ordinary);
    BOOST_CHECK(
        product
            .merkle_fold_proof_tape_fixed_offsets);
    BOOST_CHECK(
        product.merkle_fold_equations_bound);
    BOOST_CHECK(
        product
            .merkle_fold_r0_statement_manifest_only);
    BOOST_CHECK(
        product
            .merkle_fold_cs_independent_of_child_witness);
    BOOST_CHECK(
        !product
             .merkle_fold_transcript_and_opening_carry_complete);
    BOOST_CHECK(
        product
            .deep_vm_constraints_canonical_bytecode);
    BOOST_CHECK(
        product
            .deep_vm_program_root_recomputed);
    BOOST_CHECK_EQUAL(
        product.deep_vm_program_constraints,
        kDeepVmCanonicalConstraintsV1);
    BOOST_CHECK_EQUAL(
        product
            .deep_vm_statement_manifest_r0_columns,
        kDeepVmStatementScheduleColumnsV1);
    BOOST_CHECK_EQUAL(
        product.deep_vm_proof_tape_cells,
        product.deep_vm.layout.n_columns +
            kDeepVmExtensionColumnsV1 -
            kDeepVmStatementScheduleColumnsV1);
    BOOST_CHECK(
        product.deep_vm_proof_tape_cells_ordinary);
    BOOST_CHECK(
        product.deep_vm_proof_tape_fixed_offsets);
    BOOST_CHECK(
        product
            .deep_vm_schedule_independently_regenerated);
    BOOST_CHECK(
        product.deep_vm_program_and_range_bound);
    BOOST_CHECK(
        product.deep_vm_program_constants_owned);
    BOOST_CHECK(
        product.deep_vm_internal_ssa_copy_provenance);
    BOOST_CHECK(
        !product
             .deep_vm_register_precommit_root.IsNull());
    BOOST_CHECK(
        product.deep_vm_register_precommit_root ==
        product.deep_vm.preprocessed_row_group_root);
    BOOST_CHECK(
        product
            .deep_vm_r0_statement_manifest_only);
    BOOST_CHECK(
        product
            .deep_vm_cs_independent_of_child_witness);
    BOOST_CHECK(
        !product
             .deep_vm_register_challenge_carry_complete);
    BOOST_CHECK(
        !product
             .deep_vm_value_and_source_carry_complete);
    BOOST_CHECK(
        product
            .decoder_constraints_canonical_bytecode);
    BOOST_CHECK(
        product
            .decoder_program_root_recomputed);
    BOOST_CHECK_EQUAL(
        product.decoder_program_constraints,
        30U);
    BOOST_CHECK_EQUAL(
        product
            .decoder_statement_manifest_r0_columns,
        11U);
    BOOST_CHECK_EQUAL(
        product.decoder_proof_tape_cells,
        product.decoder.layout.n_columns +
            kDecoderHornerAuxColumnsV1 -
            11U);
    BOOST_CHECK(
        product
            .decoder_proof_tape_cells_ordinary);
    BOOST_CHECK(
        product
            .decoder_proof_tape_fixed_offsets);
    BOOST_CHECK(
        product
            .decoder_degree_reduced_horner_chain);
    BOOST_CHECK(
        product
            .decoder_r0_statement_manifest_only);
    BOOST_CHECK(
        !product
             .decoder_cs_independent_of_child_witness);
    BOOST_CHECK(
        product
            .decoder_challenge_columns_post_commit);
    BOOST_CHECK(
        product
            .decoder_program_challenge_independent);
    BOOST_CHECK(
        !product
             .decoder_challenge_carry_complete);
    BOOST_CHECK(
        !product
             .decoder_child_root_carry_complete);
    BOOST_CHECK_EQUAL(product.trace_rows, 524288U);
    BOOST_CHECK_EQUAL(product.trace_columns, 1443U);
    BOOST_CHECK_EQUAL(
        product.max_constraint_degree, 3U);
    BOOST_CHECK_EQUAL(product.quotient_len, 1048575U);
    BOOST_CHECK_EQUAL(
        product.commitment_coefficients, 1048576U);
    BOOST_CHECK_EQUAL(
        product.commitment_lde_rows, 16777216U);
    BOOST_CHECK_LE(
        product.commitment_lde_rows,
        kLdeRowsCapV1);
    for (uint32_t index = 0;
         index < kPhasesV1;
         ++index) {
        const auto& phase = product.phases[index];
        BOOST_CHECK_EQUAL(
            static_cast<uint32_t>(phase.phase),
            index);
        BOOST_CHECK_GT(phase.rows, 0U);
        BOOST_CHECK_GT(phase.columns, 0U);
        BOOST_CHECK_GT(phase.constraints, 0U);
    }

    BOOST_TEST_MESSAGE(
        "V11_UNIFIED_Q96"
        << " active_rows=" << product.active_rows
        << " trace_rows=" << product.trace_rows
        << " cols=" << product.trace_columns
        << " constraints=" << product.constraints
        << " degree=" << product.max_constraint_degree
        << " quotient_len=" << product.quotient_len
        << " cells=" << product.materialized_trace_cells
        << " commitment_coeffs="
        << product.commitment_coefficients
        << " lde_rows="
        << product.commitment_lde_rows
        << " static_cs=0"
        << " verifier_excludes_child_proof=0"
        << " carries_complete=0"
        << " authority=0");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_unified_verifier_air
