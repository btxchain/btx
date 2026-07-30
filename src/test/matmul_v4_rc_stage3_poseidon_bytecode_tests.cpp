// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_poseidon_bytecode.h>

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace ah = matmul::v4::rc::alg_hash;
namespace aq = matmul::v4::rc::air_quotient;
namespace ar = matmul::v4::rc::air_recurse;
namespace cb = matmul::v4::rc::constraint_bytecode;
namespace gf = matmul::v4::rc::gkr_field;
namespace pa = matmul::v4::rc::stage3_poseidon_air;

using gf::Fp3;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_poseidon_bytecode_tests,
                         BasicTestingSetup)

namespace {

gf::Fp SplitMix(uint64_t& state)
{
    state += UINT64_C(0x9e3779b97f4a7c15);
    uint64_t z = state;
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return gf::FromU64(z ^ (z >> 31));
}

// A full-entropy Fp3 row of `width` cells (all three extension coordinates
// randomized) so the affine S-box input form is exercised on genuine extension
// values, not just base-field embeddings.
std::vector<Fp3> RandomRow(uint32_t width, uint64_t seed)
{
    uint64_t state = seed;
    std::vector<Fp3> row(width);
    for (auto& cell : row) {
        cell = Fp3{SplitMix(state), SplitMix(state), SplitMix(state)};
    }
    return row;
}

ah::State StateFor(uint64_t seed)
{
    ah::State out{};
    uint64_t state = seed;
    for (auto& lane : out) lane = SplitMix(state);
    return out;
}

} // namespace

// The migrated table validates and has the exact fixed-table shape.
BOOST_AUTO_TEST_CASE(fixed_program_table_shape)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(pa::BuildFixedProgramTable(table, &why), why);
    BOOST_REQUIRE(cb::ValidateProgramTable(table, &why));

    BOOST_CHECK_EQUAL(table.programs.size(), 472U);
    BOOST_CHECK_EQUAL(table.current_width, 484U);
    BOOST_CHECK_EQUAL(table.next_width, 0U);
    BOOST_CHECK_EQUAL(table.challenge_width, 0U);
    BOOST_CHECK(cb::ProgramTableIsChallengeIndependent(table));
    for (uint32_t o = 0; o < table.programs.size(); ++o) {
        BOOST_CHECK_EQUAL(table.programs[o].constraint_ordinal, o);
        BOOST_CHECK_EQUAL(table.programs[o].declared_degree, 2U);
    }
}

// DIFFERENTIAL TEST: on random rows every migrated program evaluates to the
// SAME Fp3 value as its native std::function constraint, bit-for-bit.
BOOST_AUTO_TEST_CASE(bytecode_matches_native_on_random_rows)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE(pa::BuildFixedProgramTable(table, &why));

    const pa::Layout layout = pa::CanonicalLayout();
    const auto native = pa::BuildFixedConstraints(layout);
    BOOST_REQUIRE_EQUAL(native.size(), table.programs.size());

    const std::vector<Fp3> empty_next;
    for (uint64_t seed = 1; seed <= 24; ++seed) {
        const std::vector<Fp3> row =
            RandomRow(table.current_width, seed * UINT64_C(0xd1342543de82ef95));
        for (uint32_t o = 0; o < table.programs.size(); ++o) {
            Fp3 interpreted;
            BOOST_REQUIRE(cb::EvaluateProgram(
                table.programs[o], row, empty_next, interpreted, &why));
            const Fp3 native_value = native[o].eval(row, row);
            BOOST_CHECK_MESSAGE(
                gf::Eq(interpreted, native_value),
                "mismatch at ordinal " << o << " seed " << seed);
        }
    }
}

// On an honest Poseidon2 witness both the native builder and the migrated
// bytecode vanish on every constraint (completeness preserved).
BOOST_AUTO_TEST_CASE(bytecode_vanishes_on_honest_witness)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE(pa::BuildFixedProgramTable(table, &why));

    const pa::Layout layout = pa::CanonicalLayout();
    const auto native = pa::BuildFixedConstraints(layout);
    const std::vector<Fp3> empty_next;

    for (uint64_t seed = 1; seed <= 8; ++seed) {
        const ah::State input = StateFor(seed * UINT64_C(0x2545f4914f6cdd1d));
        const pa::Witness witness = pa::BuildWitness(layout, input);
        BOOST_REQUIRE_EQUAL(witness.row.size(), table.current_width);
        for (uint32_t o = 0; o < table.programs.size(); ++o) {
            Fp3 interpreted;
            BOOST_REQUIRE(cb::EvaluateProgram(
                table.programs[o], witness.row, empty_next, interpreted, &why));
            BOOST_CHECK(gf::IsZero(interpreted));
            BOOST_CHECK(gf::IsZero(native[o].eval(witness.row, witness.row)));
            BOOST_CHECK(gf::Eq(interpreted, native[o].eval(witness.row, witness.row)));
        }
    }
}

// The adapter that reconstructs an AirConstraintSystem from the table agrees
// with the table's own interpreter (the CheckAdapterMatchesPrograms contract).
BOOST_AUTO_TEST_CASE(adapter_matches_interpreter)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE(pa::BuildFixedProgramTable(table, &why));

    aq::AirConstraintSystem<Fp3> cs;
    BOOST_REQUIRE(cb::BuildAirConstraintSystemFromProgramTable(table, 2, cs, &why));
    BOOST_REQUIRE_EQUAL(cs.constraints.size(), table.programs.size());

    const std::vector<Fp3> row =
        RandomRow(table.current_width, UINT64_C(0xabcdef0123456789));
    const std::vector<Fp3> next(table.next_width, Fp3::Zero());
    for (uint32_t o = 0; o < table.programs.size(); ++o) {
        Fp3 interpreted;
        BOOST_REQUIRE(cb::EvaluateProgram(
            table.programs[o], row, next, interpreted, &why));
        BOOST_CHECK(gf::Eq(interpreted, cs.constraints[o].eval(row, next)));
    }
}

BOOST_AUTO_TEST_SUITE_END()
