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

BOOST_FIXTURE_TEST_SUITE(swarm_flagship_order_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(join_before_acquire_is_order)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(!cursor.Record("join", "evidence-join", err));
    BOOST_REQUIRE_EQUAL(err, "ORDER");
    BOOST_REQUIRE(!cursor.recorded("join"));
    BOOST_REQUIRE(!cursor.recorded("acquire"));
    BOOST_REQUIRE(cursor.evidence("join").empty());
    BOOST_REQUIRE(cursor.evidence("acquire").empty());
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "acquire");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(empty_evidence_on_join_is_evidence_before_order)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(!cursor.Record("join", "", err));
    BOOST_REQUIRE_EQUAL(err, "EVIDENCE");
    BOOST_REQUIRE(!cursor.recorded("join"));
    BOOST_REQUIRE(!cursor.recorded("acquire"));
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "acquire");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(later_stage_before_its_predecessor_is_order)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(!cursor.Record("coordinate", "evidence-coordinate", err));
    BOOST_REQUIRE_EQUAL(err, "ORDER");
    BOOST_REQUIRE(cursor.recorded("acquire"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "evidence-acquire");
    BOOST_REQUIRE(!cursor.recorded("join"));
    BOOST_REQUIRE(!cursor.recorded("coordinate"));
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "join");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(order_keeps_the_prefix_already_stored)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(cursor.Record("join", "evidence-join", err));
    BOOST_REQUIRE(!cursor.Record("train", "evidence-train", err));
    BOOST_REQUIRE_EQUAL(err, "ORDER");
    BOOST_REQUIRE(cursor.recorded("acquire"));
    BOOST_REQUIRE(cursor.recorded("join"));
    BOOST_REQUIRE(!cursor.recorded("coordinate"));
    BOOST_REQUIRE(!cursor.recorded("accelerate"));
    BOOST_REQUIRE(!cursor.recorded("experience"));
    BOOST_REQUIRE(!cursor.recorded("train"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "evidence-acquire");
    BOOST_REQUIRE_EQUAL(cursor.evidence("join"), "evidence-join");
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "coordinate");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(misspelled_stage_is_stage_not_order)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(!cursor.Record("Acquire", "evidence-acquire", err));
    BOOST_REQUIRE_EQUAL(err, "STAGE");
    BOOST_REQUIRE(!cursor.recorded("Acquire"));
    BOOST_REQUIRE(!cursor.recorded("acquire"));
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "acquire");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(repeat_before_the_prefix_is_order)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(!cursor.Record("repeat", "evidence-repeat", err));
    BOOST_REQUIRE_EQUAL(err, "ORDER");
    BOOST_REQUIRE(!cursor.recorded("repeat"));
    BOOST_REQUIRE(!cursor.recorded("acquire"));
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "acquire");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(after_rollback_opens_a_hole_a_later_record_is_order)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(cursor.Record("join", "evidence-join", err));
    BOOST_REQUIRE(cursor.Record("coordinate", "evidence-coordinate", err));
    BOOST_REQUIRE(cursor.Rollback("join", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!cursor.Record("coordinate", "evidence-coordinate-again", err));
    BOOST_REQUIRE_EQUAL(err, "ORDER");
    BOOST_REQUIRE(cursor.recorded("acquire"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "evidence-acquire");
    BOOST_REQUIRE(!cursor.recorded("join"));
    BOOST_REQUIRE(!cursor.recorded("coordinate"));
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "join");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(the_next_stage_after_a_prefix_is_accepted)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(cursor.Record("join", "evidence-join", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "coordinate");
    BOOST_REQUIRE(cursor.recorded("acquire"));
    BOOST_REQUIRE(cursor.recorded("join"));
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_SUITE_END()
