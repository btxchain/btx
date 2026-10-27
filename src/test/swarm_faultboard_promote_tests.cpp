// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/swarm_faultboard.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void ExpectIdle(const modelnet::SwarmFaultBoard& plane)
{
    BOOST_CHECK(!plane.qualified());
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(plane.bytes_moved() == 0);
    BOOST_CHECK(plane.atoms_moved() == 0);
    BOOST_CHECK(!plane.broadcast());
    BOOST_CHECK(!plane.mined());
    BOOST_CHECK(!plane.saved());
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_faultboard_promote_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(promotion_interrupted_keeps_the_active_head)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepHead("channel-a", "head-a", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(plane.KeepHead("channel-b", "head-b", err));
    BOOST_CHECK_EQUAL(plane.head("channel-a"), "head-a");

    BOOST_REQUIRE(plane.KeepHead("channel-a", "head-next", err));
    BOOST_CHECK_EQUAL(plane.head("channel-a"), "head-next");

    err = "prior";
    BOOST_REQUIRE(!plane.PromotionInterrupted("channel-a", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_GRADUATED");
    BOOST_CHECK_EQUAL(plane.head("channel-a"), "head-next");
    BOOST_CHECK_EQUAL(plane.head("channel-b"), "head-b");
    BOOST_CHECK(plane.rollback_count() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.PromotionInterrupted("channel-missing", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_GRADUATED");
    BOOST_CHECK_EQUAL(plane.head("channel-missing"), "");
    BOOST_CHECK(plane.rollback_count() == 0);
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(empty_previous_is_not_staged)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepHead("channel-a", "head-a", err));
    err = "prior";
    BOOST_REQUIRE(!plane.CanaryRegress("channel-a", "", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_STAGED");
    BOOST_CHECK_EQUAL(plane.head("channel-a"), "head-a");
    BOOST_CHECK(plane.rollback_count() == 0);
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(canary_regress_restores_previous_and_appends_rollback)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepHead("channel-a", "head-live", err));
    BOOST_REQUIRE(plane.KeepHead("channel-b", "head-stay", err));

    err = "prior";
    BOOST_REQUIRE(!plane.CanaryRegress("channel-a", "head-prev", err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(plane.head("channel-a"), "head-prev");
    BOOST_CHECK_EQUAL(plane.head("channel-b"), "head-stay");
    BOOST_CHECK(plane.rollback_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.CanaryRegress("channel-a", "head-prev", err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(plane.head("channel-a"), "head-prev");
    BOOST_CHECK(plane.rollback_count() == 2);

    err = "prior";
    BOOST_REQUIRE(!plane.CanaryRegress("channel-c", "head-c", err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(plane.head("channel-c"), "head-c");
    BOOST_CHECK(plane.rollback_count() == 3);
    BOOST_CHECK_EQUAL(plane.head("channel-b"), "head-stay");

    err = "prior";
    BOOST_REQUIRE(!plane.PromotionInterrupted("channel-a", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_GRADUATED");
    BOOST_CHECK_EQUAL(plane.head("channel-a"), "head-prev");
    BOOST_CHECK(plane.rollback_count() == 3);
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(conflicting_reports_are_not_averaged)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepHead("channel-a", "head-a", err));
    BOOST_REQUIRE(plane.KeepEarned("work-a", 3, err));
    err = "prior";
    BOOST_REQUIRE(!plane.ConflictingReports(err));
    BOOST_REQUIRE_EQUAL(err, "NOT_AVERAGED");
    BOOST_CHECK(!plane.qualified());
    BOOST_CHECK_EQUAL(plane.head("channel-a"), "head-a");
    BOOST_CHECK(plane.earned("work-a") == 3);
    BOOST_CHECK(plane.earned_count() == 1);
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_SUITE_END()
