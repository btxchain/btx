// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v13_proof_tape_air.h>
#include <matmul/matmul_v4_rc_stage3_v13_proof_tape_bytecode.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air {
namespace {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;
using gf::Fp3;

uint256 Root(uint8_t byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

PublicShapeV1 Shape()
{
    PublicShapeV1 out;
    out.trace_rows = 2;
    out.trace_columns = 2;
    out.quotient_len = 2;
    out.n_coeffs = 2;
    out.base_column_indices = {0};
    return out;
}

PublicBindingV1 Binding(uint64_t root_delta = 0)
{
    PublicBindingV1 out;
    out.program_root = Root(0x11);
    out.statement_root = Root(0x22);
    out.public_fs_seed = Root(0x33);
    out.proof_wire_root = Root(0x44);
    out.tape_root = {
        gf::FromU64(1 + root_delta),
        gf::FromU64(2),
        gf::FromU64(3),
        gf::FromU64(4)};
    return out;
}

uint64_t SplitMix(uint64_t& state)
{
    uint64_t z = (state +=
        UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) *
        UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) *
        UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

std::vector<Fp3> RandomRow(
    uint32_t width,
    uint64_t seed)
{
    std::vector<Fp3> out(width);
    for (auto& value : out) {
        value = Fp3{
            SplitMix(seed),
            SplitMix(seed),
            SplitMix(seed)};
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v13_proof_tape_bytecode_tests)

BOOST_AUTO_TEST_CASE(
    full_table_is_stable_complete_and_proof_independent)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildCanonicalProgramTableV1(table, &why), why);
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(table, &why), why);
    BOOST_CHECK_EQUAL(table.programs.size(), 669U);
    BOOST_CHECK_EQUAL(
        table.current_width,
        CanonicalLayoutV1().End());
    BOOST_CHECK_EQUAL(
        table.next_width,
        CanonicalLayoutV1().End());
    BOOST_CHECK_EQUAL(table.challenge_width, 0U);
    BOOST_CHECK(
        cb::ProgramTableIsChallengeIndependent(table));

    aq::AirConstraintSystem<Fp3> first;
    aq::AirConstraintSystem<Fp3> second;
    BOOST_REQUIRE(
        BuildConstraintSystemV1(
            Shape(), Binding(0), first,
            nullptr, nullptr, &why));
    BOOST_REQUIRE(
        BuildConstraintSystemV1(
            Shape(), Binding(9), second,
            nullptr, nullptr, &why));
    BOOST_REQUIRE_EQUAL(
        first.constraints.size(),
        table.programs.size());
    BOOST_REQUIRE_EQUAL(
        second.constraints.size(),
        table.programs.size());

    cb::ProgramTable rebuilt;
    BOOST_REQUIRE(
        BuildCanonicalProgramTableV1(rebuilt, &why));
    BOOST_CHECK(
        cb::CommitProgramTable(table) ==
        cb::CommitProgramTable(rebuilt));

    std::vector<unsigned char> bytes;
    BOOST_REQUIRE(
        cb::SerializeProgramTable(table, bytes, &why));
    cb::ProgramTable decoded;
    BOOST_REQUIRE(
        cb::DeserializeProgramTable(
            bytes, decoded, &why));
    BOOST_CHECK(decoded == table);
}

BOOST_AUTO_TEST_CASE(
    bytecode_matches_every_native_callback_ordinal)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE(
        BuildCanonicalProgramTableV1(table, &why));
    aq::AirConstraintSystem<Fp3> native;
    BOOST_REQUIRE(
        BuildConstraintSystemV1(
            Shape(), Binding(), native,
            nullptr, nullptr, &why));
    BOOST_REQUIRE_EQUAL(
        native.constraints.size(),
        table.programs.size());

    for (uint64_t seed = 1; seed <= 4; ++seed) {
        const std::vector<Fp3> current =
            RandomRow(
                table.current_width,
                UINT64_C(0x243f6a8885a308d3) *
                    seed);
        const std::vector<Fp3> next =
            RandomRow(
                table.next_width,
                UINT64_C(0x13198a2e03707344) *
                    seed);
        for (uint32_t ordinal = 0;
             ordinal < table.programs.size();
             ++ordinal) {
            Fp3 interpreted;
            BOOST_REQUIRE_MESSAGE(
                cb::EvaluateProgram(
                    table.programs[ordinal],
                    current, next,
                    interpreted, &why),
                "ordinal=" << ordinal << " " << why);
            const Fp3 expected =
                native.constraints[ordinal].eval(
                    current, next);
            BOOST_CHECK_MESSAGE(
                gf::Eq(interpreted, expected),
                "ordinal=" << ordinal <<
                " seed=" << seed);
            BOOST_CHECK(
                native.constraints[ordinal].kind ==
                table.programs[ordinal].kind);
            BOOST_CHECK_EQUAL(
                native.constraints[ordinal].
                    alg_degree,
                table.programs[ordinal].
                    declared_degree);
        }
    }
}

BOOST_AUTO_TEST_CASE(
    terminal_root_is_r0_owned_not_embedded_in_program)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE(
        BuildCanonicalProgramTableV1(table, &why));
    aq::AirConstraintSystem<Fp3> native;
    LayoutV1 layout;
    BOOST_REQUIRE(
        BuildConstraintSystemV1(
            Shape(), Binding(), native,
            &layout, nullptr, &why));

    const uint32_t first_terminal = 664;
    BOOST_REQUIRE(
        native.constraints[first_terminal].kind ==
        aq::AirKind::kLastRow);
    std::vector<Fp3> current(
        layout.End(), Fp3::Zero());
    std::vector<Fp3> next(
        layout.End(), Fp3::Zero());
    Fp3 before;
    Fp3 after;
    BOOST_REQUIRE(
        cb::EvaluateProgram(
            table.programs[first_terminal],
            current, next, before, &why));
    current[layout.ExpectedTapeRoot(0)] =
        Fp3::One();
    BOOST_REQUIRE(
        cb::EvaluateProgram(
            table.programs[first_terminal],
            current, next, after, &why));
    BOOST_CHECK(
        gf::Eq(
            gf::Sub(before, after),
            Fp3::One()));

    bool found_root_column = false;
    for (const auto& [column, values] :
         native.preprocessed) {
        if (column !=
            layout.ExpectedTapeRoot(0)) {
            continue;
        }
        found_root_column = true;
        BOOST_REQUIRE_EQUAL(
            values.size(), native.n_rows);
        BOOST_CHECK(
            std::all_of(
                values.begin(), values.end(),
                [&](const Fp3& value) {
                    return gf::Eq(
                        value,
                        Fp3::FromFp(
                            Binding().tape_root[0]));
                }));
    }
    BOOST_CHECK(found_root_column);
}

BOOST_AUTO_TEST_CASE(
    canonical_adapter_discards_every_opaque_relation_callback)
{
    std::string why;
    aq::AirConstraintSystem<Fp3> native;
    aq::AirConstraintSystem<Fp3> canonical;
    cb::ProgramTable table;
    LayoutV1 native_layout;
    LayoutV1 canonical_layout;
    ScheduleV1 native_schedule;
    ScheduleV1 canonical_schedule;
    BOOST_REQUIRE(
        BuildConstraintSystemV1(
            Shape(), Binding(), native,
            &native_layout, &native_schedule,
            &why));
    BOOST_REQUIRE(
        BuildCanonicalConstraintSystemV1(
            Shape(), Binding(), canonical,
            &canonical_layout,
            &canonical_schedule,
            &table, &why));
    BOOST_CHECK_EQUAL(
        canonical.constraints.size(), 669U);
    BOOST_CHECK_EQUAL(
        canonical.constraints.size(),
        native.constraints.size());
    BOOST_CHECK_EQUAL(
        canonical.n_rows, native.n_rows);
    BOOST_CHECK_EQUAL(
        canonical.n_columns,
        native.n_columns);
    BOOST_CHECK(
        canonical_layout.End() ==
        native_layout.End());
    BOOST_CHECK_EQUAL(
        canonical_schedule.source_records,
        native_schedule.source_records);
    BOOST_REQUIRE_EQUAL(
        canonical.preprocessed.size(),
        native.preprocessed.size());
    for (uint32_t index = 0;
         index < canonical.preprocessed.size();
         ++index) {
        BOOST_CHECK_EQUAL(
            canonical.preprocessed[index].first,
            native.preprocessed[index].first);
        BOOST_REQUIRE_EQUAL(
            canonical.preprocessed[index].
                second.size(),
            native.preprocessed[index].
                second.size());
        for (uint32_t row = 0;
             row <
                canonical.preprocessed[index].
                    second.size();
             ++row) {
            BOOST_CHECK(
                gf::Eq(
                    canonical.preprocessed[index].
                        second[row],
                    native.preprocessed[index].
                        second[row]));
        }
    }
    BOOST_CHECK(
        canonical.preprocessed_pin_ood ==
        native.preprocessed_pin_ood);
    BOOST_CHECK(
        std::all_of(
            canonical.constraints.begin(),
            canonical.constraints.end(),
            [](const auto& constraint) {
                return constraint.name ==
                    "stage3.constraint_bytecode.v1";
            }));
    BOOST_CHECK_EQUAL(
        table.programs.size(),
        canonical.constraints.size());
}

BOOST_AUTO_TEST_CASE(
    acceptance_only_or_mutated_table_is_not_the_full_relation)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE(
        BuildCanonicalProgramTableV1(table, &why));
    const uint256 honest_root =
        cb::CommitProgramTable(table);

    cb::ProgramTable truncated = table;
    truncated.programs.erase(
        truncated.programs.begin(),
        truncated.programs.end() - 5);
    for (uint32_t ordinal = 0;
         ordinal < truncated.programs.size();
         ++ordinal) {
        truncated.programs[ordinal].
            constraint_ordinal = ordinal;
    }
    BOOST_REQUIRE(
        cb::ValidateProgramTable(
            truncated, &why));
    BOOST_CHECK(
        truncated.programs.size() != 669);
    BOOST_CHECK(
        cb::CommitProgramTable(truncated) !=
        honest_root);

    cb::ProgramTable mutated = table;
    mutated.programs.back().
        instructions.back().lhs =
        CanonicalLayoutV1().
            ExpectedTapeRoot(0);
    BOOST_REQUIRE(
        cb::ValidateProgramTable(mutated, &why));
    BOOST_CHECK(
        cb::CommitProgramTable(mutated) !=
        honest_root);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air
