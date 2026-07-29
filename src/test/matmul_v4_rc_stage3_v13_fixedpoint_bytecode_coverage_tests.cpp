// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_v13_fixedpoint_bytecode_coverage.h>

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace coverage =
    rc::stage3_v13_fixedpoint_bytecode_coverage;
namespace gf = rc::gkr_field;

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

BOOST_AUTO_TEST_SUITE_END()
