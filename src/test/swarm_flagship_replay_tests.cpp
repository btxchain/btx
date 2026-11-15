// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flagship/cursor.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectDark(const modelnet::SwarmFlagshipCursor& cursor)
{
    BOOST_REQUIRE(!cursor.passed());
    BOOST_REQUIRE(!cursor.gpu_passed());
    BOOST_REQUIRE(!cursor.windows_passed());
    BOOST_REQUIRE(!cursor.pay_passed());
    BOOST_REQUIRE(!cursor.launched());
    BOOST_REQUIRE(!cursor.gpu());
    BOOST_REQUIRE(!cursor.broadcast());
    BOOST_REQUIRE(cursor.bytes_moved() == std::uint64_t{0});
    BOOST_REQUIRE(cursor.atoms_moved() == std::uint64_t{0});
    BOOST_REQUIRE_EQUAL(cursor.automatic_spend(), "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_flagship_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(same_evidence_again_is_replay_and_keeps_the_first)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(cursor.recorded("acquire"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "evidence-acquire");
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "join");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(different_evidence_is_conflict_and_keeps_the_first)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(!cursor.Record("acquire", "evidence-other", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE(cursor.recorded("acquire"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "evidence-acquire");
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "join");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(empty_evidence_on_a_recorded_stage_is_evidence_not_replay)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(!cursor.Record("acquire", "", err));
    BOOST_REQUIRE_EQUAL(err, "EVIDENCE");
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "evidence-acquire");
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "join");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(replay_does_not_move_next_stage)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(cursor.Record("join", "evidence-join", err));
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "coordinate");

    BOOST_REQUIRE(!cursor.Record("join", "evidence-join", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "coordinate");
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "evidence-acquire");
    BOOST_REQUIRE_EQUAL(cursor.evidence("join"), "evidence-join");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(conflict_on_a_later_stage_keeps_the_prefix)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(cursor.Record("join", "evidence-join", err));
    BOOST_REQUIRE(cursor.Record("coordinate", "evidence-coordinate", err));
    BOOST_REQUIRE(!cursor.Record("coordinate", "evidence-coordinate-other", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "evidence-acquire");
    BOOST_REQUIRE_EQUAL(cursor.evidence("join"), "evidence-join");
    BOOST_REQUIRE_EQUAL(cursor.evidence("coordinate"), "evidence-coordinate");
    BOOST_REQUIRE(!cursor.recorded("accelerate"));
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "accelerate");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(third_record_of_the_original_evidence_is_replay)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "alpha", err));
    BOOST_REQUIRE(!cursor.Record("acquire", "beta", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE(!cursor.Record("acquire", "alpha", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "alpha");
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "join");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(case_difference_is_conflict)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "Evidence-acquire", err));
    BOOST_REQUIRE(!cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "Evidence-acquire");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(replay_and_conflict_do_not_pass)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(!cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(!cursor.Record("acquire", "other", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE(!cursor.passed());
    BOOST_REQUIRE(!cursor.gpu_passed());
    BOOST_REQUIRE(!cursor.windows_passed());
    BOOST_REQUIRE(!cursor.pay_passed());
    BOOST_REQUIRE(!cursor.launched());
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_SUITE_END()
