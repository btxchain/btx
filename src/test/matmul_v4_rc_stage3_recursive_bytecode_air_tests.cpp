// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_recursive_bytecode_air.h>

namespace matmul::v4::rc::recursive_bytecode_air {
namespace {

namespace cb = constraint_bytecode;
namespace gf = gkr_field;

gf::Fp PowBase(gf::Fp base, uint64_t exponent)
{
    gf::Fp out = 1;
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            out = gf::Mul(out, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

gf::Fp3 Pow3(gf::Fp3 base, uint32_t exponent)
{
    gf::Fp3 out = gf::Fp3::One();
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            out = gf::Mul(out, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

QuotientDomainV1 Domain()
{
    QuotientDomainV1 out;
    out.trace_rows = 4;
    out.evaluation_rows = 16;
    out.evaluation_omega = gf::Fp3::FromFp(
        PowBase(
            UINT64_C(0x185629dcda58878c),
            uint64_t{1} << 28));
    out.trace_omega =
        Pow3(out.evaluation_omega, 4);
    out.coset_shift =
        gf::FromU64_3(7);
    return out;
}

cb::ProgramTable Table()
{
    cb::ProgramTable out;
    out.role = RCStage3RelationRole::CoupledBank;
    out.current_width = 2;
    out.next_width = 2;

    cb::Program product;
    product.role = out.role;
    product.constraint_ordinal = 0;
    product.kind = air_quotient::AirKind::kEverywhere;
    product.declared_degree = 2;
    product.current_width = 2;
    product.next_width = 2;
    product.instructions = {
        {cb::Opcode::Current, 0, 0, gf::Fp3::Zero()},
        {cb::Opcode::Current, 1, 0, gf::Fp3::Zero()},
        {cb::Opcode::Mul, 0, 1, gf::Fp3::Zero()},
    };
    out.programs.push_back(product);

    cb::Program transition;
    transition.role = out.role;
    transition.constraint_ordinal = 1;
    transition.kind = air_quotient::AirKind::kTransition;
    transition.declared_degree = 1;
    transition.current_width = 2;
    transition.next_width = 2;
    transition.instructions = {
        {cb::Opcode::Next, 0, 0, gf::Fp3::Zero()},
        {cb::Opcode::Current, 1, 0, gf::Fp3::Zero()},
        {cb::Opcode::Sub, 0, 1, gf::Fp3::Zero()},
    };
    out.programs.push_back(transition);
    return out;
}

cb::ProgramTable ChallengeTable()
{
    cb::ProgramTable out;
    out.role = RCStage3RelationRole::CoupledBank;
    out.current_width = 2;
    out.next_width = 2;
    out.challenge_width = 1;

    cb::Program product;
    product.role = out.role;
    product.constraint_ordinal = 0;
    product.kind = air_quotient::AirKind::kEverywhere;
    product.declared_degree = 2;
    product.current_width = out.current_width;
    product.next_width = out.next_width;
    product.challenge_width = out.challenge_width;
    product.instructions = {
        {cb::Opcode::Current, 0, 0, gf::Fp3::Zero()},
        {cb::Opcode::Challenge, 0, 0, gf::Fp3::Zero()},
        {cb::Opcode::Mul, 0, 1, gf::Fp3::Zero()},
    };
    out.programs.push_back(std::move(product));
    return out;
}

std::vector<QuotientOpeningRowV1> Rows()
{
    const auto domain = Domain();
    const gf::Fp3 h_last =
        gf::Inv(domain.trace_omega);
    std::vector<QuotientOpeningRowV1> out;
    for (uint32_t row = 0; row < 3; ++row) {
        QuotientOpeningRowV1 opening;
        opening.current = {
            gf::FromU64_3(row + 2),
            gf::FromU64_3(row + 5),
        };
        opening.next = {
            gf::FromU64_3(row + 7),
            gf::FromU64_3(row + 11),
        };
        opening.constraint_lambda =
            gf::FromU64_3(13 + row);
        opening.query_index = row + 1;
        opening.evaluation_point =
            gf::Mul(
                domain.coset_shift,
                Pow3(
                    domain.evaluation_omega,
                    opening.query_index));
        opening.next_evaluation_point =
            gf::Mul(
                domain.trace_omega,
                opening.evaluation_point);
        const gf::Fp3 product =
            gf::Mul(
                opening.current[0],
                opening.current[1]);
        const gf::Fp3 transition =
            gf::Sub(
                opening.next[0],
                opening.current[1]);
        const gf::Fp3 selector =
            gf::Sub(
                opening.evaluation_point,
                h_last);
        const gf::Fp3 weighted =
            gf::Add(
                product,
                gf::Mul(
                    opening.constraint_lambda,
                    gf::Mul(
                        selector,
                        transition)));
        const gf::Fp3 zh =
            gf::Sub(
                Pow3(
                    opening.evaluation_point,
                    domain.trace_rows),
                gf::Fp3::One());
        opening.quotient_opening =
            gf::Mul(weighted, gf::Inv(zh));
        out.push_back(std::move(opening));
    }
    return out;
}

std::vector<QuotientOpeningRowV1> ChallengeRows()
{
    const auto domain = Domain();
    auto out = Rows();
    for (uint32_t row = 0; row < out.size(); ++row) {
        auto& opening = out[row];
        opening.challenge = {gf::FromU64_3(101 + row)};
        const gf::Fp3 terminal = gf::Mul(
            opening.current[0], opening.challenge[0]);
        const gf::Fp3 zh = gf::Sub(
            Pow3(
                opening.evaluation_point,
                domain.trace_rows),
            gf::Fp3::One());
        opening.quotient_opening =
            gf::Mul(terminal, gf::Inv(zh));
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_recursive_bytecode_air_tests)

BOOST_AUTO_TEST_CASE(
    canonical_ssa_executes_and_feeds_weighted_quotient_residual)
{
    const auto table = Table();
    BOOST_REQUIRE(cb::ValidateProgramTable(table));
    const auto key =
        cb::CommitProgramTableAlgHash(table);
    const auto domain = Domain();
    const auto rows = Rows();
    const auto candidate =
        BuildCanonicalBytecodeQuotientAirV1(
            table, key, domain, rows);
    BOOST_REQUIRE_MESSAGE(
        candidate.valid, candidate.note);
    BOOST_CHECK(
        candidate.current_next_direct_aliases);
    BOOST_CHECK(
        candidate.selectors_derived_from_evaluation_point);
    BOOST_CHECK(
        candidate.lambda_direct_alias);
    BOOST_CHECK(
        candidate.next_opening_point_is_omega_z);
    BOOST_CHECK(
        candidate.quotient_vanishing_identity_constrained);
    BOOST_CHECK(
        !candidate.proof_sources_authenticated_by_parent);
    BOOST_CHECK(
        !candidate.current_next_values_bound_to_pcs_openings);
    BOOST_CHECK(
        candidate.query_index_to_evaluation_point_in_air);
    BOOST_CHECK(
        candidate.canonical_ssa_executes);
    BOOST_CHECK(
        candidate.terminals_feed_quotient_residual);
    BOOST_CHECK(
        candidate.padding_zero_constrained);
    BOOST_CHECK(!candidate.constant_width_universal);
    BOOST_CHECK(!candidate.recursive_fixed_point);
    BOOST_CHECK(!candidate.authority);
    std::string why;
    BOOST_CHECK_MESSAGE(
        ValidateCanonicalBytecodeQuotientAirV1(
            table, key, domain,
            rows, candidate, &why),
        why);
}

BOOST_AUTO_TEST_CASE(
    source_register_residual_and_program_substitutions_fail)
{
    const auto table = Table();
    const auto key =
        cb::CommitProgramTableAlgHash(table);
    const auto domain = Domain();
    const auto rows = Rows();
    const auto candidate =
        BuildCanonicalBytecodeQuotientAirV1(
            table, key, domain, rows);
    BOOST_REQUIRE(candidate.valid);
    std::string why;

    auto source_attack = candidate;
    source_attack.witness[
        source_attack.source_current_base][0] =
        gf::Add(
            source_attack.witness[
                source_attack.source_current_base][0],
            gf::Fp3::One());
    BOOST_CHECK(
        !ValidateCanonicalBytecodeQuotientAirV1(
            table, key, domain, rows,
            source_attack, &why));

    auto register_attack = candidate;
    register_attack.witness[
        register_attack.register_base][0] =
        gf::Add(
            register_attack.witness[
                register_attack.register_base][0],
            gf::Fp3::One());
    BOOST_CHECK(
        !ValidateCanonicalBytecodeQuotientAirV1(
            table, key, domain, rows,
            register_attack, &why));

    auto residual_rows = rows;
    residual_rows[0].quotient_opening =
        gf::Add(
            residual_rows[0]
                .quotient_opening,
            gf::Fp3::One());
    BOOST_CHECK(
        !BuildCanonicalBytecodeQuotientAirV1(
             table, key, domain,
             residual_rows)
             .valid);

    auto next_point_rows = rows;
    next_point_rows[0].next_evaluation_point =
        gf::Add(
            next_point_rows[0]
                .next_evaluation_point,
            gf::Fp3::One());
    BOOST_CHECK(
        !BuildCanonicalBytecodeQuotientAirV1(
             table, key, domain,
             next_point_rows)
             .valid);

    auto query_rows = rows;
    ++query_rows[0].query_index;
    BOOST_CHECK(
        !BuildCanonicalBytecodeQuotientAirV1(
             table, key, domain,
             query_rows)
             .valid);

    auto changed_table = table;
    changed_table.programs[0]
        .instructions[2].opcode =
        cb::Opcode::Add;
    changed_table.programs[0]
        .declared_degree = 1;
    BOOST_REQUIRE(
        cb::ValidateProgramTable(changed_table));
    BOOST_CHECK(
        cb::CommitProgramTableAlgHash(
            changed_table) != key);
    BOOST_CHECK(
        !BuildCanonicalBytecodeQuotientAirV1(
             changed_table, key,
             domain, rows)
             .valid);
}

BOOST_AUTO_TEST_CASE(
    post_challenge_columns_execute_and_are_directly_aliased)
{
    const auto table = ChallengeTable();
    BOOST_REQUIRE(cb::ValidateProgramTable(table));
    const auto key =
        cb::CommitProgramTableAlgHash(table);
    const auto domain = Domain();
    const auto rows = ChallengeRows();
    const auto candidate =
        BuildCanonicalBytecodeQuotientAirV1(
            table, key, domain, rows);
    BOOST_REQUIRE_MESSAGE(
        candidate.valid, candidate.note);
    BOOST_CHECK(
        candidate.challenge_columns_direct_aliases);
    BOOST_CHECK_EQUAL(
        candidate.interpreter_challenge_base,
        candidate.source_quotient_opening + 1 +
            table.current_width + table.next_width);
    std::string why;
    BOOST_CHECK_MESSAGE(
        ValidateCanonicalBytecodeQuotientAirV1(
            table, key, domain,
            rows, candidate, &why),
        why);

    auto source_attack = candidate;
    source_attack.witness[
        source_attack.source_challenge_base][0] =
        gf::Add(
            source_attack.witness[
                source_attack.source_challenge_base][0],
            gf::Fp3::One());
    std::vector<gf::Fp3> attacked_row(
        source_attack.columns, gf::Fp3::Zero());
    std::vector<gf::Fp3> attacked_next(
        source_attack.columns, gf::Fp3::Zero());
    for (uint32_t column = 0;
         column < source_attack.columns; ++column) {
        attacked_row[column] =
            source_attack.witness[column][0];
        attacked_next[column] =
            source_attack.witness[column][1];
    }
    bool alias_constraint_rejects = false;
    for (const auto& constraint :
         source_attack.cs.constraints) {
        if (std::string{constraint.name} ==
                "stage3.recursive_bytecode.challenge_alias" &&
            !gf::IsZero(
                constraint.eval(
                    attacked_row, attacked_next))) {
            alias_constraint_rejects = true;
        }
    }
    BOOST_CHECK(alias_constraint_rejects);
    BOOST_CHECK(
        !ValidateCanonicalBytecodeQuotientAirV1(
            table, key, domain, rows,
            source_attack, &why));

    auto interpreter_attack = candidate;
    interpreter_attack.witness[
        interpreter_attack.interpreter_challenge_base][0] =
        gf::Add(
            interpreter_attack.witness[
                interpreter_attack.interpreter_challenge_base][0],
            gf::Fp3::One());
    BOOST_CHECK(
        !ValidateCanonicalBytecodeQuotientAirV1(
            table, key, domain, rows,
            interpreter_attack, &why));

    auto missing_challenge = rows;
    missing_challenge[0].challenge.clear();
    BOOST_CHECK(
        !BuildCanonicalBytecodeQuotientAirV1(
             table, key, domain,
             missing_challenge)
             .valid);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::recursive_bytecode_air
