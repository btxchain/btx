// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>

#include <algorithm>
#include <cstdlib>
#include <vector>

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace cb = rc::constraint_bytecode;
namespace fp = rc::recursive_fixedpoint;
namespace gf = rc::gkr_field;

namespace {

uint256 Seed(uint8_t tag)
{
    uint256 out;
    for (uint32_t i = 0; i < out.size(); ++i) {
        out.begin()[i] =
            static_cast<unsigned char>(
                tag + 13U * i);
    }
    if (out.IsNull()) out.begin()[0] = 1;
    return out;
}

cb::Instruction Current(uint32_t column)
{
    cb::Instruction out;
    out.opcode = cb::Opcode::Current;
    out.lhs = column;
    return out;
}

cb::Instruction Next(uint32_t column)
{
    cb::Instruction out;
    out.opcode = cb::Opcode::Next;
    out.lhs = column;
    return out;
}

cb::Instruction Constant(uint64_t value)
{
    cb::Instruction out;
    out.opcode = cb::Opcode::Constant;
    out.constant =
        gf::Fp3::FromFp(
            gf::FromU64(value));
    return out;
}

cb::Instruction Binary(
    cb::Opcode opcode,
    uint32_t lhs,
    uint32_t rhs)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = lhs;
    out.rhs = rhs;
    return out;
}

cb::ProgramTable CanonicalTable()
{
    cb::ProgramTable table;
    table.role =
        rc::RCStage3RelationRole::
            EpisodeDigest;
    table.current_width = 1;
    table.next_width = 1;

    cb::Program boolean;
    boolean.role = table.role;
    boolean.constraint_ordinal = 0;
    boolean.kind = aq::AirKind::kEverywhere;
    boolean.declared_degree = 2;
    boolean.current_width = 1;
    boolean.next_width = 1;
    // x * (x - 1)
    boolean.instructions = {
        Current(0),
        Constant(1),
        Binary(cb::Opcode::Sub, 0, 1),
        Binary(cb::Opcode::Mul, 0, 2),
    };

    cb::Program transition;
    transition.role = table.role;
    transition.constraint_ordinal = 1;
    transition.kind = aq::AirKind::kTransition;
    transition.declared_degree = 1;
    transition.current_width = 1;
    transition.next_width = 1;
    // next(x) - x
    transition.instructions = {
        Next(0),
        Current(0),
        Binary(cb::Opcode::Sub, 0, 1),
    };
    table.programs = {
        std::move(boolean),
        std::move(transition),
    };
    return table;
}

struct CanonicalChild {
    cb::ProgramTable table;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>>
        columns;
    fp::AlgAirProof proof;
    uint256 seed{};
};

CanonicalChild BuildChild(uint8_t tag)
{
    CanonicalChild out;
    out.table = CanonicalTable();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            out.table, 16, out.cs, &why),
        why);
    out.columns.assign(
        out.cs.n_columns,
        std::vector<gf::Fp3>(
            out.cs.n_rows,
            gf::Fp3::Zero()));
    out.seed = Seed(tag);
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3,
            aq::AirFriBackendAlg<gf::Fp3>>(
                out.cs, out.columns,
                out.seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok &&
            proved.division_exact,
        proved.note);
    out.proof = proved.proof;
    return out;
}

uint32_t FindSelectedRow(
    const fp::FoldBusComposition& composition,
    uint32_t column)
{
    for (uint32_t row = 0;
         row < composition.combined.n_rows;
         ++row) {
        if (!gf::IsZero(
                composition.columns[
                    column][row])) {
            return row;
        }
    }
    return composition.combined.n_rows;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_child_acceptance_tests)

BOOST_AUTO_TEST_CASE(
    canonical_per_point_join_consumes_every_packed_child)
{
    const CanonicalChild left =
        BuildChild(0x21);
    const CanonicalChild right =
        BuildChild(0x31);
    fp::FoldBusComposition joined =
        fp::BuildCanonicalFoldBusCompositionMultiV1(
            {left.cs, right.cs},
            {left.proof, right.proof},
            {left.seed, right.seed});
    BOOST_REQUIRE_MESSAGE(joined.valid, joined.note);
    BOOST_CHECK(
        joined.deep_per_point_transition_join);
    BOOST_CHECK_EQUAL(
        joined.per_point_children_expected, 2U);
    BOOST_CHECK_EQUAL(
        joined.per_point_children_joined, 2U);
    BOOST_REQUIRE_EQUAL(
        joined
            .child_per_point_program_commitments
            .size(),
        2U);
    const uint256 table_commitment =
        cb::CommitProgramTable(left.table);
    BOOST_REQUIRE(!table_commitment.IsNull());
    for (const uint256& commitment :
         joined
             .child_per_point_program_commitments) {
        BOOST_CHECK(
            commitment == table_commitment);
    }
    BOOST_CHECK_EQUAL(joined.violations, 0U);

    // Each attachment is a separate constant-width, time-multiplexed bus.
    // Mutating the authenticated next-row value consumed by the transition
    // program breaks the parent AIR, not a host-side counter.
    const fp::BytecodeBusLayout left_layout(
        joined.deep.End());
    const uint32_t next_kind = 3;
    const uint32_t next_row =
        FindSelectedRow(
            joined,
            left_layout.RowKind(next_kind));
    BOOST_REQUIRE_LT(
        next_row, joined.combined.n_rows);
    auto bad_transition = joined.columns;
    bad_transition[
        left_layout.Value(3)][next_row] =
        gf::Add(
            bad_transition[
                left_layout.Value(3)][next_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined,
            bad_transition),
        0U);

    const uint32_t quotient_kind = 8;
    const uint32_t quotient_row =
        FindSelectedRow(
            joined,
            left_layout.RowKind(
                quotient_kind));
    BOOST_REQUIRE_LT(
        quotient_row,
        joined.combined.n_rows);
    auto bad_quotient = joined.columns;
    bad_quotient[
        left_layout.Value(3)][quotient_row] =
        gf::Add(
            bad_quotient[
                left_layout.Value(3)]
                [quotient_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fp::CountHashOpeningViolations(
            joined.combined,
            bad_quotient),
        0U);
}

BOOST_AUTO_TEST_CASE(
    proof_program_and_exact_domain_substitution_fail_closed)
{
    const CanonicalChild child =
        BuildChild(0x41);

    auto bad_proof = child.proof;
    BOOST_REQUIRE(
        !bad_proof.batch.queries.empty());
    BOOST_REQUIRE(
        !bad_proof.batch.queries[0]
             .row.values.empty());
    bad_proof.batch.queries[0]
        .row.values[0] =
        gf::Add(
            bad_proof.batch.queries[0]
                .row.values[0],
            gf::Fp3::One());
    const auto proof_substitution =
        fp::BuildCanonicalFoldBusCompositionV1(
            child.cs, bad_proof,
            child.seed);
    BOOST_CHECK(!proof_substitution.valid);

    auto base =
        fp::BuildFoldBusComposition(
            child.cs, child.proof,
            child.seed);
    BOOST_REQUIRE_MESSAGE(base.valid, base.note);
    auto wrong_program = child.cs;
    wrong_program.constraints[0]
        .canonical_program_table_root =
        Seed(0x51);
    const auto program_substitution =
        fp::AttachCanonicalChildAcceptanceV1(
            base, {wrong_program});
    BOOST_CHECK(
        program_substitution
            .provenance_present);
    BOOST_CHECK(!program_substitution.valid);
    BOOST_CHECK(!base.valid);

    base =
        fp::BuildFoldBusComposition(
            child.cs, child.proof,
            child.seed);
    BOOST_REQUIRE_MESSAGE(base.valid, base.note);
    auto wrong_domain = child.cs;
    wrong_domain.n_rows *= 2;
    const auto domain_substitution =
        fp::AttachCanonicalChildAcceptanceV1(
            base, {wrong_domain});
    BOOST_CHECK(
        domain_substitution
            .provenance_present);
    BOOST_CHECK(!domain_substitution.valid);
    BOOST_CHECK(!base.valid);

    base =
        fp::BuildFoldBusComposition(
            child.cs, child.proof,
            child.seed);
    BOOST_REQUIRE_MESSAGE(base.valid, base.note);
    auto partial = child.cs;
    partial.constraints[0]
        .canonical_program_table_wire.reset();
    const auto partial_substitution =
        fp::AttachCanonicalChildAcceptanceV1(
            base, {partial});
    BOOST_CHECK(
        partial_substitution
            .provenance_present);
    BOOST_CHECK(!partial_substitution.valid);
    BOOST_CHECK(!base.valid);
}

BOOST_AUTO_TEST_CASE(
    canonical_parent_proof_rejects_context_and_opening_substitution)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_CHILD_ACCEPTANCE_PARENT_PROOF") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_CHILD_ACCEPTANCE_PARENT_PROOF=1 "
            "for the proof-level canonical child-acceptance test");
        return;
    }

    const CanonicalChild left =
        BuildChild(0x61);
    const CanonicalChild right =
        BuildChild(0x71);
    const std::vector<uint256> child_seeds{
        left.seed, right.seed};
    const fp::FoldBusComposition joined =
        fp::BuildCanonicalFoldBusCompositionMultiV1(
            {left.cs, right.cs},
            {left.proof, right.proof},
            child_seeds);
    BOOST_REQUIRE_MESSAGE(joined.valid, joined.note);
    BOOST_REQUIRE(
        joined.deep_per_point_transition_join);

    const uint256 context = Seed(0x81);
    const uint256 parent_seed =
        fp::ComputeNarrowMultiChildParentFsSeedV1(
            joined, child_seeds, context);
    BOOST_REQUIRE(!parent_seed.IsNull());
    const auto proved =
        aq::AirQuotientProveRows(
            joined.combined, joined.columns,
            parent_seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact,
        proved.note);

    std::string why;
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRows(
            joined.combined, proved.proof,
            parent_seed, &why),
        why);

    const uint256 substituted_seed =
        fp::ComputeNarrowMultiChildParentFsSeedV1(
            joined, child_seeds, Seed(0x82));
    BOOST_REQUIRE(!substituted_seed.IsNull());
    BOOST_REQUIRE(substituted_seed != parent_seed);
    why.clear();
    BOOST_CHECK(
        !aq::AirQuotientVerifyRows(
            joined.combined, proved.proof,
            substituted_seed, &why));

    auto tampered = proved.proof;
    BOOST_REQUIRE(
        !tampered.batch.queries.empty());
    BOOST_REQUIRE(
        !tampered.batch.queries[0]
             .steps.empty());
    tampered.batch.queries[0]
        .steps[0].even =
        gf::Add(
            tampered.batch.queries[0]
                .steps[0].even,
            gf::Fp3::One());
    why.clear();
    BOOST_CHECK(
        !aq::AirQuotientVerifyRows(
            joined.combined, tampered,
            parent_seed, &why));
}

BOOST_AUTO_TEST_SUITE_END()
