// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_p2_consumer_bridge.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_unified_verifier_air.h>

#include <hash.h>

namespace matmul::v4::rc::stage3_multirow_v11_unified_verifier_air {
namespace {

namespace backend = stage3_multirow_v11_backend;
namespace cb = constraint_bytecode;
namespace consumer = stage3_multirow_p2_consumer_bridge;
namespace tp = stage3_multirow_p2_transcript;

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
    cs.n_rows = 256;
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
        2, std::vector<gf::Fp3>(256));
    for (uint32_t row = 0; row < 256; ++row) {
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
    out.expected_child_statement_root = H(101);

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
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_unified_verifier_air_tests)

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
    BOOST_CHECK_EQUAL(product.trace_rows, 524288U);
    BOOST_CHECK_EQUAL(product.trace_columns, 1489U);
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
