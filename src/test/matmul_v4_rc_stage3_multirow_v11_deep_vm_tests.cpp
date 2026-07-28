// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_deep_vm.h>

#include <algorithm>
#include <cstdlib>
#include <limits>

namespace matmul::v4::rc::stage3_multirow_v11_deep_vm {
namespace {

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
                gf::Mul(
                    current[0],
                    gf::Fp3::FromFp(2)));
        }});
    return cs;
}

std::vector<std::vector<gf::Fp3>> TransitionTrace()
{
    std::vector<std::vector<gf::Fp3>> out(
        2, std::vector<gf::Fp3>(256));
    for (uint32_t row = 0; row < 256; ++row) {
        out[0][row] = gf::Fp3::FromFp(row + 9);
        out[1][row] = gf::Mul(
            out[0][row], gf::Fp3::FromFp(2));
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
    cb::Program transition;
    transition.role = RCStage3RelationRole::EpisodeGemm;
    transition.constraint_ordinal = 0;
    transition.kind = aq::AirKind::kTransition;
    transition.declared_degree = 1;
    transition.current_width = 2;
    transition.next_width = 2;
    transition.instructions = {
        Load(cb::Opcode::Next, 0),
        Load(cb::Opcode::Current, 0),
        Binary(cb::Opcode::Sub, 0, 1),
        Constant(1),
        Binary(cb::Opcode::Sub, 2, 3),
    };

    cb::Program everywhere;
    everywhere.role = RCStage3RelationRole::EpisodeGemm;
    everywhere.constraint_ordinal = 1;
    everywhere.kind = aq::AirKind::kEverywhere;
    everywhere.declared_degree = 1;
    everywhere.current_width = 2;
    everywhere.next_width = 2;
    everywhere.instructions = {
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
    out.programs = {transition, everywhere};
    return out;
}

cb::ProgramTable TransitionChallengePrograms()
{
    cb::Program transition;
    transition.role = RCStage3RelationRole::EpisodeGemm;
    transition.constraint_ordinal = 0;
    transition.kind = aq::AirKind::kTransition;
    transition.declared_degree = 1;
    transition.current_width = 2;
    transition.next_width = 2;
    transition.challenge_width = 2;
    transition.instructions = {
        Load(cb::Opcode::Next, 0),
        Load(cb::Opcode::Current, 0),
        Binary(cb::Opcode::Sub, 0, 1),
        Load(cb::Opcode::Challenge, 0),
        Binary(cb::Opcode::Sub, 2, 3),
    };

    cb::Program everywhere;
    everywhere.role = RCStage3RelationRole::EpisodeGemm;
    everywhere.constraint_ordinal = 1;
    everywhere.kind = aq::AirKind::kEverywhere;
    // Challenge is conservatively degree one in canonical bytecode.
    everywhere.declared_degree = 2;
    everywhere.current_width = 2;
    everywhere.next_width = 2;
    everywhere.challenge_width = 2;
    everywhere.instructions = {
        Load(cb::Opcode::Current, 1),
        Load(cb::Opcode::Current, 0),
        Load(cb::Opcode::Challenge, 1),
        Binary(cb::Opcode::Mul, 1, 2),
        Binary(cb::Opcode::Sub, 0, 3),
    };

    cb::ProgramTable out;
    out.role = RCStage3RelationRole::EpisodeGemm;
    out.current_width = 2;
    out.next_width = 2;
    out.challenge_width = 2;
    out.programs = {transition, everywhere};
    return out;
}

struct Fixture {
    backend::AirProveResultV1 proved;
    tp::ReceiptV1 transcript;
    cb::ProgramTable table;
    alg_hash::Digest program_root{};
};

const Fixture& Honest()
{
    static const Fixture fixture = [] {
        Fixture out;
        out.proved = backend::ProveAirQuotientV1(
            TransitionAir(), TransitionTrace(),
            {0}, uint256::ONE);
        BOOST_REQUIRE_MESSAGE(
            out.proved.ok, out.proved.note);
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            backend::VerifyV1(
                out.proved.proximity.proof,
                &out.transcript, &why),
            why);
        out.table = TransitionPrograms();
        BOOST_REQUIRE_MESSAGE(
            cb::ValidateProgramTable(out.table, &why), why);
        out.program_root =
            cb::CommitProgramTableAlgHash(out.table);
        return out;
    }();
    return fixture;
}

uint32_t FindRow(
    const ProductV1& product, uint32_t flag)
{
    for (uint32_t row = 0; row < product.real_rows; ++row) {
        if (gf::Eq(
                product.columns[flag][row],
                gf::Fp3::One())) {
            return row;
        }
    }
    BOOST_FAIL("missing operation row");
    return 0;
}

std::vector<uint32_t> FindRows(
    const ProductV1& product, uint32_t flag)
{
    std::vector<uint32_t> out;
    for (uint32_t row = 0;
         row < product.real_rows;
         ++row) {
        if (gf::Eq(
                product.columns[flag][row],
                gf::Fp3::One())) {
            out.push_back(row);
        }
    }
    return out;
}

void RequireInexactProofRejected(
    const ProductV1& product,
    const std::vector<std::vector<gf::Fp3>>& columns,
    bool expect_preprocessed_reject = false)
{
    BOOST_REQUIRE_GT(
        RecountViolationsV1(product, columns), 0U);
    aq::AirProveOptions options;
    options.force_commit_on_inexact = true;
    const auto forced =
        aq::AirQuotientProveRowsSplitRap(
            product.cs, columns,
            product.preprocessed_columns,
            uint256::ONE, options);
    if (!forced.ok) {
        BOOST_CHECK(expect_preprocessed_reject);
        BOOST_CHECK(
            forced.note.find(
                "preprocessed_row_group_pin_mismatch") !=
            std::string::npos);
        return;
    }
    BOOST_REQUIRE_MESSAGE(forced.ok, forced.note);
    BOOST_CHECK(!forced.division_exact);
    std::string why;
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            product.cs, forced.proof,
            product.preprocessed_columns,
            uint256::ONE, &why));
}

uint32_t NamedViolationsAtRow(
    const ProductV1& product,
    const std::vector<std::vector<gf::Fp3>>& columns,
    uint32_t row,
    const std::string& name)
{
    std::vector<gf::Fp3> current(
        product.cs.n_columns);
    std::vector<gf::Fp3> next(
        product.cs.n_columns);
    const uint32_t next_row =
        (row + 1) % product.cs.n_rows;
    for (uint32_t column = 0;
         column < product.cs.n_columns;
         ++column) {
        current[column] = columns[column][row];
        next[column] = columns[column][next_row];
    }
    uint32_t out = 0;
    for (const auto& constraint :
         product.cs.constraints) {
        if (constraint.name != nullptr &&
            name == constraint.name &&
            !gf::IsZero(
                constraint.eval(current, next))) {
            ++out;
        }
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_deep_vm_tests)

BOOST_AUTO_TEST_CASE(
    actual_v11_abi_deep_vm_and_quotient_relations_close)
{
    const auto& fixture = Honest();
    const auto product = BuildProductV1(
        fixture.proved.proximity.proof,
        fixture.transcript,
        fixture.table, fixture.program_root, 0, 4);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK_EQUAL(
        product.layout.n_columns,
        CanonicalLayoutV1().n_columns);
    BOOST_CHECK_EQUAL(product.layout.n_columns, 281U);
    BOOST_CHECK_LE(product.max_constraint_degree, 2U);
    BOOST_CHECK_EQUAL(product.query_count, 4U);
    BOOST_CHECK_EQUAL(product.quotient_rows, 4U);
    BOOST_CHECK_EQUAL(product.deep_term_rows, 12U);
    BOOST_CHECK_EQUAL(product.vm_instruction_rows, 40U);
    BOOST_CHECK(product.canonical_abi);
    BOOST_CHECK(product.transcript_receipt_verified);
    BOOST_CHECK(product.backend_proof_verified);
    BOOST_CHECK(product.literal_current_next_refs);
    BOOST_CHECK(product.duplicate_queries_preserved);
    BOOST_CHECK(product.deep_rlc_air_constrained);
    BOOST_CHECK(product.denominator_inverse_air_constrained);
    BOOST_CHECK(product.first_fold_equality_air_constrained);
    BOOST_CHECK(product.quotient_identity_air_constrained);
    BOOST_CHECK(product.canonical_bytecode_vm_air_constrained);
    BOOST_CHECK(product.lambda_accumulation_air_constrained);
    BOOST_CHECK(product.exact_program_root_checked);
    BOOST_CHECK(product.ordered_preprocessed_root_pinned);
    BOOST_CHECK(product.quotient_tape_cells_ordinary);
    BOOST_CHECK(product.quotient_tape_u32_canonical);
    BOOST_CHECK(product.quotient_tape_value_reconstructed);
    BOOST_CHECK(product.quotient_tape_fixed_offsets_r0_bound);
    BOOST_CHECK(product.quotient_tape_all_consumers_joined);
    BOOST_CHECK(product.quotient_tape_acceptance_constrained);
    BOOST_CHECK(!product.same_parent_decoder_aliases);
    BOOST_CHECK(!product.recursive_authority_ready);

    const auto one = BuildProductV1(
        fixture.proved.proximity.proof,
        fixture.transcript,
        fixture.table, fixture.program_root, 0, 1);
    BOOST_REQUIRE_MESSAGE(one.valid, one.note);
    BOOST_CHECK_EQUAL(
        one.layout.n_columns, product.layout.n_columns);
    BOOST_CHECK_LT(one.trace_rows, product.trace_rows);
}

BOOST_AUTO_TEST_CASE(
    verifier_owned_child_challenges_execute_and_substitutions_reject)
{
    const auto& fixture = Honest();
    const cb::ProgramTable table =
        TransitionChallengePrograms();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(table, &why), why);
    const auto root =
        cb::CommitProgramTableAlgHash(table);
    const std::vector<gf::Fp3> public_challenge{
        gf::Fp3::One(),
        gf::Fp3::FromFp(2),
    };
    const auto product = BuildProductV1(
        fixture.proved.proximity.proof,
        fixture.transcript,
        table, root, public_challenge, 0, 2);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(product.verifier_owned_challenge_bound);
    BOOST_CHECK_EQUAL(
        product.program_challenge.size(), 2U);
    BOOST_CHECK(
        std::find(
            product.preprocessed_columns.begin(),
            product.preprocessed_columns.end(),
            product.layout.op_challenge) !=
        product.preprocessed_columns.end());
    BOOST_CHECK(
        std::find(
            product.preprocessed_columns.begin(),
            product.preprocessed_columns.end(),
            product.layout.operand_lhs) !=
        product.preprocessed_columns.end());

    auto substituted = public_challenge;
    substituted[0] = gf::Fp3::FromFp(2);
    const auto substitution_rejected =
        BuildProductV1(
            fixture.proved.proximity.proof,
            fixture.transcript,
            table, root, substituted, 0, 2);
    BOOST_CHECK(!substitution_rejected.valid);

    const auto missing_rejected =
        BuildProductV1(
            fixture.proved.proximity.proof,
            fixture.transcript,
            table, root,
            std::vector<gf::Fp3>{gf::Fp3::One()},
            0, 2);
    BOOST_CHECK(!missing_rejected.valid);

    auto witness_attack = product.columns;
    const uint32_t challenge_row =
        FindRow(product, product.layout.op_challenge);
    witness_attack[product.layout.operand_lhs]
                  [challenge_row] =
        gf::Add(
            witness_attack[product.layout.operand_lhs]
                          [challenge_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(product, witness_attack), 0U);
    const auto attacked_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            product.cs, witness_attack,
            product.preprocessed_columns);
    BOOST_REQUIRE(attacked_session.valid);
    BOOST_CHECK(
        attacked_session.base_row_commitment !=
        product.preprocessed_row_group_root);
}

BOOST_AUTO_TEST_CASE(
    inverse_current_next_quotient_and_vm_tampers_violate_air)
{
    const auto& fixture = Honest();
    const auto product = BuildProductV1(
        fixture.proved.proximity.proof,
        fixture.transcript,
        fixture.table, fixture.program_root, 0, 2);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);

    auto inverse = product.columns;
    const uint32_t final_row = FindRow(
        product, product.layout.deep_finalize);
    inverse[product.layout.inv_x_minus_z1][final_row].c0 ^= 1;
    BOOST_CHECK_GT(
        RecountViolationsV1(product, inverse), 0U);

    auto deep_aux = product.columns;
    deep_aux[product.layout.deep_rhs_term1][final_row] =
        gf::Add(
            deep_aux[
                product.layout.deep_rhs_term1][final_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(product, deep_aux), 0U);

    auto current = product.columns;
    const uint32_t term_row = FindRow(
        product, product.layout.deep_term);
    current[product.layout.current_value][term_row].c0 ^= 1;
    BOOST_CHECK_GT(
        RecountViolationsV1(product, current), 0U);

    auto term_aux = product.columns;
    term_aux[product.layout.u_contribution][term_row] =
        gf::Add(
            term_aux[
                product.layout.u_contribution][term_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(product, term_aux), 0U);

    auto vm = product.columns;
    const uint32_t vm_row = FindRow(
        product, product.layout.vm_instruction);
    vm[product.layout.instruction_result][vm_row].c0 ^= 1;
    BOOST_CHECK_GT(RecountViolationsV1(product, vm), 0U);

    auto vm_aux = product.columns;
    vm_aux[product.layout.selected_result][vm_row] =
        gf::Add(
            vm_aux[
                product.layout.selected_result][vm_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(product, vm_aux), 0U);

    auto quotient = product.columns;
    const uint32_t quotient_row = FindRow(
        product, product.layout.quotient_identity);
    quotient[product.layout.quotient_value][quotient_row].c0 ^= 1;
    BOOST_CHECK_GT(
        RecountViolationsV1(product, quotient), 0U);

    auto quotient_aux = product.columns;
    quotient_aux[
        product.layout.quotient_product][quotient_row] =
        gf::Add(
            quotient_aux[
                product.layout.quotient_product][quotient_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(product, quotient_aux), 0U);

    const auto quotient_rows = FindRows(
        product, product.layout.quotient_identity);
    BOOST_REQUIRE_EQUAL(quotient_rows.size(), 2U);

    auto tape_value = product.columns;
    tape_value[
        product.layout.quotient_tape_limb[0]]
        [quotient_rows[0]] =
            gf::Add(
                tape_value[
                    product.layout.quotient_tape_limb[0]]
                    [quotient_rows[0]],
                gf::Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(product, tape_value), 0U);

    auto tape_swap = product.columns;
    BOOST_REQUIRE(
        !gf::Eq(
            tape_swap[
                product.layout.quotient_tape_limb[0]]
                [quotient_rows[0]],
            tape_swap[
                product.layout.quotient_tape_limb[1]]
                [quotient_rows[0]]));
    std::swap(
        tape_swap[
            product.layout.quotient_tape_limb[0]]
            [quotient_rows[0]],
        tape_swap[
            product.layout.quotient_tape_limb[1]]
            [quotient_rows[0]]);
    for (uint32_t bit = 0;
         bit < kU32TapeBitsV1;
         ++bit) {
        std::swap(
            tape_swap[
                product.layout.quotient_tape_bit[0][bit]]
                [quotient_rows[0]],
            tape_swap[
                product.layout.quotient_tape_bit[1][bit]]
                [quotient_rows[0]]);
    }
    BOOST_CHECK_GT(
        RecountViolationsV1(product, tape_swap), 0U);

    auto tape_offset = product.columns;
    tape_offset[product.layout.source_address]
               [quotient_rows[0]] =
        gf::Add(
            tape_offset[product.layout.source_address]
                       [quotient_rows[0]],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(product, tape_offset), 0U);

    auto tape_accept = product.columns;
    tape_accept[
        product.layout.quotient_tape_accept]
        [quotient_rows[0]] = gf::Fp3::Zero();
    BOOST_CHECK_GT(
        RecountViolationsV1(product, tape_accept), 0U);

    // The non-canonical limbs (lo=1, hi=0xffffffff) reconstruct the
    // Goldilocks modulus and therefore alias field zero.  The value
    // reconstruction alone accepts that equality; the explicit canonicality
    // relation must reject it.
    auto modulus_alias = product.columns;
    for (uint32_t limb = 0;
         limb < kFp3TapeLimbsV1;
         ++limb) {
        const uint32_t value =
            limb == 0 ? 1U :
            limb == 1
                ? std::numeric_limits<uint32_t>::max()
                : 0U;
        modulus_alias[
            product.layout.quotient_tape_limb[limb]]
            [quotient_rows[0]] =
                gf::Fp3::FromFp(value);
        for (uint32_t bit = 0;
             bit < kU32TapeBitsV1;
             ++bit) {
            modulus_alias[
                product.layout.quotient_tape_bit[
                    limb][bit]]
                [quotient_rows[0]] =
                    gf::Fp3::FromFp(
                        (value >> bit) & 1U);
        }
    }
    modulus_alias[product.layout.quotient_tape_value]
                 [quotient_rows[0]] =
        gf::Fp3::Zero();
    modulus_alias[
        product.layout.quotient_high_is_max[0]]
        [quotient_rows[0]] = gf::Fp3::One();
    modulus_alias[
        product.layout.quotient_high_delta_inverse[0]]
        [quotient_rows[0]] = gf::Fp3::Zero();
    BOOST_CHECK_EQUAL(
        NamedViolationsAtRow(
            product, modulus_alias,
            quotient_rows[0],
            "stage3.v11.deep_vm."
            "quotient_tape_fp3_reconstruct"),
        0U);
    BOOST_CHECK_GT(
        NamedViolationsAtRow(
            product, modulus_alias,
            quotient_rows[0],
            "stage3.v11.deep_vm."
            "quotient_tape_goldilocks_canonical"),
        0U);

    // Changing a proof-owned input and its local arithmetic together still
    // cannot evade the fixed ordered preprocessed row commitment.
    auto both = product.columns;
    both[product.layout.current_value][term_row].c0 ^= 1;
    both[product.layout.u_after][term_row] =
        gf::Add(
            both[product.layout.u_before][term_row],
            gf::Mul(
                both[product.layout.coefficient][term_row],
                gf::Mul(
                    both[product.layout.x_power][term_row],
                    both[product.layout.current_value][term_row])));
    BOOST_CHECK_GT(
        RecountViolationsV1(product, both), 0U);
}

BOOST_AUTO_TEST_CASE(
    optional_proof_level_quotient_tape_attacks_reject)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_V11_DEEP_TAPE_PROOF") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_V11_DEEP_TAPE_PROOF=1 for "
            "proof-level fixed-offset tape attacks");
        return;
    }
    const auto& fixture = Honest();
    const auto product = BuildProductV1(
        fixture.proved.proximity.proof,
        fixture.transcript,
        fixture.table, fixture.program_root, 0, 1);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    const auto quotient_rows = FindRows(
        product, product.layout.quotient_identity);
    BOOST_REQUIRE_EQUAL(quotient_rows.size(), 1U);
    const uint32_t row = quotient_rows.front();

    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            product.cs, product.columns,
            product.preprocessed_columns,
            uint256::ONE);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRap(
            product.cs, proved.proof,
            product.preprocessed_columns,
            uint256::ONE, &why),
        why);

    auto value_attack = product.columns;
    value_attack[
        product.layout.quotient_tape_limb[0]][row] =
        gf::Add(
            value_attack[
                product.layout.quotient_tape_limb[0]][row],
            gf::Fp3::One());
    RequireInexactProofRejected(product, value_attack);

    auto cell_swap = product.columns;
    BOOST_REQUIRE(
        !gf::Eq(
            cell_swap[
                product.layout.quotient_tape_limb[0]][row],
            cell_swap[
                product.layout.quotient_tape_limb[1]][row]));
    std::swap(
        cell_swap[
            product.layout.quotient_tape_limb[0]][row],
        cell_swap[
            product.layout.quotient_tape_limb[1]][row]);
    for (uint32_t bit = 0;
         bit < kU32TapeBitsV1;
         ++bit) {
        std::swap(
            cell_swap[
                product.layout.quotient_tape_bit[0][bit]][row],
            cell_swap[
                product.layout.quotient_tape_bit[1][bit]][row]);
    }
    RequireInexactProofRejected(product, cell_swap);

    auto offset_attack = product.columns;
    offset_attack[product.layout.source_address][row] =
        gf::Add(
            offset_attack[product.layout.source_address][row],
            gf::Fp3::One());
    RequireInexactProofRejected(
        product, offset_attack, true);
}

BOOST_AUTO_TEST_CASE(
    ood_next_query_order_and_program_root_substitutions_reject)
{
    const auto& fixture = Honest();

    auto wrong_root = fixture.program_root;
    wrong_root[0] ^= 1;
    const auto root_rejected = BuildProductV1(
        fixture.proved.proximity.proof,
        fixture.transcript,
        fixture.table, wrong_root, 0, 1);
    BOOST_CHECK(!root_rejected.valid);

    auto wrong_program = fixture.table;
    wrong_program.programs[0].instructions[3].constant =
        gf::Fp3::FromFp(2);
    const auto program_rejected = BuildProductV1(
        fixture.proved.proximity.proof,
        fixture.transcript,
        wrong_program, fixture.program_root, 0, 1);
    BOOST_CHECK(!program_rejected.valid);

    auto ood = fixture.proved.proximity.proof;
    ood.envelope.split.batch.evals_z1[0].c0 ^= 1;
    const auto ood_rejected = BuildProductV1(
        ood, fixture.transcript,
        fixture.table, fixture.program_root, 0, 1);
    BOOST_CHECK(!ood_rejected.valid);

    auto next = fixture.proved.proximity.proof;
    next.envelope.split.next_trace_group_rows[0][0]
        .values[0].c0 ^= 1;
    const auto next_rejected = BuildProductV1(
        next, fixture.transcript,
        fixture.table, fixture.program_root, 0, 1);
    BOOST_CHECK(!next_rejected.valid);

    auto reordered = fixture.proved.proximity.proof;
    std::swap(
        reordered.envelope.split.batch.queries[0],
        reordered.envelope.split.batch.queries[1]);
    std::swap(
        reordered.envelope.split.next_trace_group_rows[0],
        reordered.envelope.split.next_trace_group_rows[1]);
    const auto reorder_rejected = BuildProductV1(
        reordered, fixture.transcript,
        fixture.table, fixture.program_root, 0, 1);
    BOOST_CHECK(!reorder_rejected.valid);
}

BOOST_AUTO_TEST_CASE(readiness_stays_fail_closed)
{
    const auto readiness = CurrentReadinessV1();
    BOOST_CHECK(readiness.deep_rlc_executable);
    BOOST_CHECK(readiness.denominator_inverse_executable);
    BOOST_CHECK(readiness.first_fold_link_executable);
    BOOST_CHECK(readiness.quotient_identity_executable);
    BOOST_CHECK(readiness.canonical_bytecode_vm_executable);
    BOOST_CHECK(readiness.lambda_accumulation_executable);
    BOOST_CHECK(!readiness.same_parent_decoder_aliases_executable);
    BOOST_CHECK(!readiness.recursive_authority_ready);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_deep_vm
