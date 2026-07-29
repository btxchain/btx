// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_semantic_endpoint_parent_bytecode.h>

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace bc =
    rc::stage3_semantic_endpoint_parent_bytecode;
namespace cb = rc::constraint_bytecode;
namespace fp = rc::recursive_fixedpoint;
namespace gf = rc::gkr_field;

namespace {

fp::SemanticEndpointReceiptTerminalLayoutV1 Layout()
{
    // The canonical table may read an already-existing eight-port opening
    // bank below its newly allocated terminal layout.
    return fp::SemanticEndpointReceiptTerminalLayoutV1(
        256, 64);
}

std::vector<gf::Fp3> Values(
    uint32_t count, uint64_t salt)
{
    std::vector<gf::Fp3> out(
        count, gf::Fp3::Zero());
    for (uint32_t i = 0; i < count; ++i) {
        out[i] = {
            gf::FromU64(salt + 3U * i + 1U),
            gf::FromU64(salt + 5U * i + 2U),
            gf::FromU64(salt + 7U * i + 3U),
        };
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_semantic_endpoint_parent_bytecode_tests)

BOOST_AUTO_TEST_CASE(
    canonical_table_matches_native_math_for_every_family)
{
    const auto layout = Layout();
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        bc::BuildCanonicalProgramTableV1(
            layout, table, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        bc::IsCanonicalProgramTableV1(
            layout, table, &why),
        why);
    BOOST_CHECK(
        cb::ProgramTableIsChallengeIndependent(table));
    BOOST_REQUIRE_EQUAL(
        table.programs.size(),
        bc::kCanonicalConstraintCountV1);
    BOOST_CHECK_EQUAL(
        table.programs[2].declared_degree, 3U);
    BOOST_CHECK_EQUAL(
        table.programs[19].declared_degree, 3U);
    const uint256 commitment =
        cb::CommitProgramTable(table);
    BOOST_REQUIRE(!commitment.IsNull());

    const auto current =
        Values(layout.End(), 0x1234U);
    const auto next =
        Values(layout.End(), 0x9876U);
    const std::vector<gf::Fp3> challenges{
        Values(1, 0x201U)[0],
        Values(1, 0x301U)[0],
        Values(1, 0x401U)[0],
        Values(1, 0x501U)[0],
    };
    for (uint32_t ordinal = 0;
         ordinal < table.programs.size();
         ++ordinal) {
        gf::Fp3 interpreted = gf::Fp3::Zero();
        gf::Fp3 native = gf::Fp3::Zero();
        BOOST_REQUIRE_MESSAGE(
            cb::EvaluateProgram(
                table.programs[ordinal],
                current, next, challenges,
                interpreted, &why),
            why);
        BOOST_REQUIRE_MESSAGE(
            bc::EvaluateNativeConstraintV1(
                layout, ordinal,
                current, next, challenges,
                native, &why),
            why);
        BOOST_CHECK_MESSAGE(
            gf::Eq(interpreted, native),
            "ordinal=" << ordinal);
    }

    aq::AirConstraintSystem<gf::Fp3> adapted;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table, 8, challenges, adapted, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        adapted.constraints.size(),
        table.programs.size());
    // Transition degree is honestly three:
    // (1-role_end)*(running + active*inverse).
    BOOST_CHECK_EQUAL(
        adapted.MaxComposedDegreeBound(), 22U);
    BOOST_CHECK_EQUAL(adapted.QuotientLen(), 15U);
    for (const auto& constraint : adapted.constraints) {
        BOOST_CHECK(
            constraint.canonical_program_table_root ==
            commitment);
        BOOST_CHECK(
            constraint.canonical_program_table_wire);
        BOOST_CHECK(
            constraint.canonical_program_challenges);
    }
}

BOOST_AUTO_TEST_CASE(
    opcode_and_operand_substitutions_reject)
{
    const auto layout = Layout();
    cb::ProgramTable canonical;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        bc::BuildCanonicalProgramTableV1(
            layout, canonical, &why),
        why);

    auto opcode_attack = canonical;
    BOOST_REQUIRE(
        opcode_attack.programs[0]
            .instructions.back().opcode ==
        cb::Opcode::Mul);
    opcode_attack.programs[0]
        .instructions.back().opcode =
        cb::Opcode::Add;
    BOOST_CHECK(
        !cb::ValidateProgramTable(
            opcode_attack, &why));
    BOOST_CHECK(
        !bc::IsCanonicalProgramTableV1(
            layout, opcode_attack, &why));

    auto degree_attack = canonical;
    degree_attack.programs[2].declared_degree = 2;
    BOOST_CHECK(
        !cb::ValidateProgramTable(
            degree_attack, &why));
    BOOST_CHECK(
        !bc::IsCanonicalProgramTableV1(
            layout, degree_attack, &why));

    auto operand_attack = canonical;
    // Program 0 is active*(root_value-root_expected).  Redirect the
    // verifier-owned expected-root load to the address column: the mutated
    // table remains syntactically valid but is not the canonical relation.
    BOOST_REQUIRE(
        operand_attack.programs[0]
            .instructions[2].opcode ==
        cb::Opcode::Current);
    operand_attack.programs[0]
        .instructions[2].lhs =
        layout.address;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(
            operand_attack, &why),
        why);
    BOOST_CHECK(
        cb::CommitProgramTable(operand_attack) !=
        cb::CommitProgramTable(canonical));
    BOOST_CHECK(
        !bc::IsCanonicalProgramTableV1(
            layout, operand_attack, &why));

    auto current =
        Values(layout.End(), 0x701U);
    const auto next =
        Values(layout.End(), 0x801U);
    const std::vector<gf::Fp3> challenges{
        Values(1, 0x901U)[0],
        Values(1, 0xa01U)[0],
        Values(1, 0xb01U)[0],
        Values(1, 0xc01U)[0],
    };
    current[layout.active] = gf::Fp3::One();
    current[layout.root_expected] =
        current[layout.root_value];
    current[layout.address] =
        gf::Add(
            current[layout.root_value],
            gf::Fp3::One());
    gf::Fp3 honest = gf::Fp3::One();
    gf::Fp3 forged = gf::Fp3::Zero();
    BOOST_REQUIRE(
        cb::EvaluateProgram(
            canonical.programs[0],
            current, next, challenges,
            honest, &why));
    BOOST_REQUIRE(
        cb::EvaluateProgram(
            operand_attack.programs[0],
            current, next, challenges,
            forged, &why));
    BOOST_CHECK(gf::IsZero(honest));
    BOOST_CHECK(!gf::IsZero(forged));
}

BOOST_AUTO_TEST_SUITE_END()
