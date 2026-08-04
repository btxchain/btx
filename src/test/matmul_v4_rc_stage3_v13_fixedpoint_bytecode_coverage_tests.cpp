// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_v13_fixedpoint_bytecode_coverage.h>
#include <matmul/matmul_v4_rc_stage3_v13_composer_glue_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_v13_proof_tape_bytecode.h>

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace coverage =
    rc::stage3_v13_fixedpoint_bytecode_coverage;
namespace glue =
    rc::stage3_v13_composer_glue_bytecode;
namespace gf = rc::gkr_field;
namespace tape =
    rc::stage3_multirow_v13_proof_tape_air;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v13_fixedpoint_bytecode_coverage_tests)

BOOST_AUTO_TEST_CASE(
    canonical_vertical_programs_are_real_but_not_horizontal_parity)
{
    const auto assessed =
        coverage::AssessCanonicalVerticalProgramsV1();
    BOOST_CHECK_EQUAL(
        assessed.phase_tables, 5U);
    BOOST_CHECK(assessed.programs > 0);
    BOOST_CHECK(assessed.serialized_bytes > 0);
    BOOST_CHECK(
        assessed.every_table_valid);
    BOOST_CHECK(
        assessed.every_root_nonzero);
    BOOST_CHECK(
        assessed
            .every_table_challenge_value_independent);
    BOOST_CHECK(
        assessed.canonical_vertical_foundation);
    BOOST_CHECK(
        !assessed
             .horizontal_to_vertical_parity_proven);
    BOOST_CHECK(
        !assessed.recursive_reentry_ready);
}

BOOST_AUTO_TEST_CASE(
    acceptance_only_and_unknown_family_do_not_close_reentry)
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 8;
    cs.n_columns = 3;
    cs.constraints.push_back({
        "stage3.v13_two_child.accept_one",
        aq::AirKind::kFirstRow,
        1,
        [](const auto& current,
           const auto&) {
            return current[0];
        }});
    auto assessed =
        coverage::AssessReentryCoverageV1(cs);
    BOOST_CHECK(
        assessed
            .acceptance_only_attack_rejected);
    BOOST_CHECK(
        assessed
            .unknown_family_attack_rejected);
    BOOST_CHECK(
        !assessed.horizontal
             .inventory_complete);
    BOOST_CHECK(
        !assessed.recursive_reentry_ready);

    cs.constraints.front().name =
        "stage3.attack.unregistered_relation";
    const auto unknown =
        coverage::AssessCallbackCoverageV1(cs);
    BOOST_CHECK_EQUAL(
        unknown.unknown_constraints, 1U);
    BOOST_CHECK(
        !unknown.inventory_complete);
    BOOST_CHECK(
        !unknown
             .whole_parent_program_reentry_ready);
}

BOOST_AUTO_TEST_CASE(
    diagnostic_bytecode_name_does_not_supply_program_provenance)
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 8;
    cs.n_columns = 3;
    cs.constraints.push_back({
        "stage3.constraint_bytecode.v1",
        aq::AirKind::kEverywhere,
        1,
        [](const auto& current,
           const auto&) {
            return current[0];
        }});
    const auto unproved =
        coverage::AssessCallbackCoverageV1(cs);
    BOOST_CHECK_EQUAL(
        unproved.bytecode_adapter_named_constraints,
        1U);
    BOOST_CHECK_EQUAL(
        unproved
            .canonical_program_provenance_constraints,
        0U);
    BOOST_CHECK_EQUAL(
        unproved.native_or_unproven_constraints,
        1U);
    BOOST_CHECK(
        !unproved.all_constraints_canonical_bytecode);

    cs.constraints.front()
        .canonical_program_table_root =
        uint256::ONE;
    const auto partial =
        coverage::AssessCallbackCoverageV1(cs);
    BOOST_CHECK_EQUAL(
        partial.invalid_program_provenance_constraints,
        1U);
    BOOST_CHECK(
        !partial.all_constraints_canonical_bytecode);
}

BOOST_AUTO_TEST_CASE(
    composer_glue_is_canonical_bytecode_with_exact_provenance)
{
    const std::vector<glue::ConstraintV1> specs{
        {glue::FormulaV1::EqualCurrent,
         aq::AirKind::kEverywhere, 0, 1, 0},
        {glue::FormulaV1::EqualOne,
         aq::AirKind::kFirstRow, 0, 0, 0},
        {glue::FormulaV1::Product,
         aq::AirKind::kEverywhere, 2, 0, 1},
        {glue::FormulaV1::CarryTransition,
         aq::AirKind::kTransition, 3, 0, 0},
        {glue::FormulaV1::SelectedEqual,
         aq::AirKind::kEverywhere, 4, 0, 1},
    };
    rc::constraint_bytecode::ProgramTable table;
    std::string why;
    BOOST_REQUIRE(
        glue::BuildCanonicalProgramTableV1(
            5, specs, table, &why));
    BOOST_CHECK(
        rc::constraint_bytecode::
            ProgramTableIsChallengeIndependent(table));

    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 8;
    cs.n_columns = 5;
    BOOST_REQUIRE(
        glue::AppendCanonicalConstraintsV1(
            table, cs.n_rows, {}, cs,
            nullptr, &why));
    BOOST_REQUIRE_EQUAL(
        cs.constraints.size(), specs.size());

    std::vector<gf::Fp3> current{
        gf::Fp3::One(),
        gf::Fp3::One(),
        gf::Fp3::One(),
        gf::FromU64_3(7),
        gf::Fp3::One(),
    };
    std::vector<gf::Fp3> next = current;
    for (uint32_t ordinal = 0;
         ordinal < cs.constraints.size();
         ++ordinal) {
        const auto& constraint =
            cs.constraints[ordinal];
        BOOST_CHECK(
            gf::IsZero(
                constraint.eval(
                    current, next)));
        BOOST_CHECK(
            !constraint
                 .canonical_program_table_root
                 .IsNull());
        BOOST_CHECK_EQUAL(
            constraint.canonical_program_ordinal,
            ordinal);
    }

    current[2] = gf::FromU64_3(2);
    BOOST_CHECK(
        !gf::IsZero(
            cs.constraints[2].eval(
                current, next)));
}

BOOST_AUTO_TEST_CASE(
    canonical_tape_inventory_requires_exact_relocated_program_and_ordinals)
{
    rc::constraint_bytecode::ProgramTable source;
    std::string why;
    BOOST_REQUIRE(
        tape::BuildCanonicalProgramTableV1(
            source, &why));
    constexpr uint32_t kBase = 17;
    auto relocated = source;
    relocated.current_width += kBase;
    relocated.next_width += kBase;
    for (auto& program : relocated.programs) {
        program.current_width += kBase;
        program.next_width += kBase;
        for (auto& instruction :
             program.instructions) {
            if (instruction.opcode ==
                    rc::constraint_bytecode::
                        Opcode::Current ||
                instruction.opcode ==
                    rc::constraint_bytecode::
                        Opcode::Next) {
                instruction.lhs += kBase;
            }
        }
    }
    aq::AirConstraintSystem<gf::Fp3> cs;
    BOOST_REQUIRE(
        rc::constraint_bytecode::
            BuildAirConstraintSystemFromProgramTable(
                relocated, 8, cs, &why));
    const auto complete =
        coverage::AssessCallbackCoverageV1(cs);
    BOOST_CHECK_EQUAL(
        complete.canonical_tape_constraints,
        relocated.programs.size());
    BOOST_CHECK_EQUAL(
        complete.canonical_tape_program_tables,
        1U);
    BOOST_CHECK_EQUAL(
        complete
            .complete_canonical_tape_program_tables,
        1U);
    BOOST_CHECK(
        complete.canonical_tape_inventory_complete);

    auto truncated = cs;
    truncated.constraints.pop_back();
    const auto missing =
        coverage::AssessCallbackCoverageV1(
            truncated);
    BOOST_CHECK_EQUAL(
        missing.canonical_tape_program_tables,
        1U);
    BOOST_CHECK_EQUAL(
        missing
            .complete_canonical_tape_program_tables,
        0U);
    BOOST_CHECK(
        !missing.canonical_tape_inventory_complete);

    auto wrong_metadata = cs;
    wrong_metadata.constraints.front().alg_degree += 1;
    const auto metadata_forged =
        coverage::AssessCallbackCoverageV1(
            wrong_metadata);
    BOOST_CHECK(
        metadata_forged
            .invalid_program_provenance_constraints >
        0);
    BOOST_CHECK(
        !metadata_forged
             .canonical_tape_inventory_complete);

    auto copied_source_root = cs;
    const uint256 source_root =
        rc::constraint_bytecode::
            CommitProgramTable(source);
    for (auto& constraint :
         copied_source_root.constraints) {
        constraint.canonical_program_table_root =
            source_root;
    }
    const auto forged =
        coverage::AssessCallbackCoverageV1(
            copied_source_root);
    BOOST_CHECK_EQUAL(
        forged.canonical_tape_constraints,
        0U);
    BOOST_CHECK(
        forged.invalid_program_provenance_constraints >
        0);
    BOOST_CHECK(
        !forged.canonical_tape_inventory_complete);
}

BOOST_AUTO_TEST_SUITE_END()
