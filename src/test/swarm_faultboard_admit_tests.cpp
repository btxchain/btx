// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/swarm_faultboard.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void ExpectClosed(const modelnet::SwarmFaultBoard& plane)
{
    BOOST_CHECK(!plane.admitted());
    BOOST_CHECK(!plane.running());
    BOOST_CHECK(!plane.qualified());
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(!plane.saved());
    BOOST_CHECK(!plane.broadcast());
    BOOST_CHECK(!plane.mined());
    BOOST_CHECK(plane.bytes_moved() == 0);
    BOOST_CHECK(plane.atoms_moved() == 0);
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_faultboard_admit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(dataset_withdrawn_does_not_start_a_run)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepEarned("work-a", 1, err));
    err = "prior";
    BOOST_REQUIRE(!plane.DatasetWithdrawn(err));
    BOOST_REQUIRE_EQUAL(err, "DATASET");
    BOOST_CHECK(!plane.running());
    BOOST_CHECK(plane.earned_count() == 1);
    BOOST_CHECK(plane.earned("work-a") == 1);
    ExpectClosed(plane);
}

BOOST_AUTO_TEST_CASE(false_compat_is_not_admitted)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepClaim("task-a", "worker-a", err));
    err = "prior";
    BOOST_REQUIRE(!plane.FalseCompat(err));
    BOOST_REQUIRE_EQUAL(err, "FAMILY_NOT_COMPAT");
    BOOST_CHECK(!plane.admitted());
    BOOST_CHECK(plane.claim_count() == 1);
    BOOST_CHECK_EQUAL(plane.claim("task-a"), "worker-a");
    ExpectClosed(plane);
}

BOOST_AUTO_TEST_CASE(permanent_gone_without_claim_or_earned_is_lost)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepResult("task-a", "receipt-a", err));
    BOOST_REQUIRE(plane.KeepHead("channel-a", "head-a", err));
    BOOST_REQUIRE(plane.KeepCheckpoint("ckpt-a", err));
    err = "prior";
    BOOST_REQUIRE(!plane.PermanentGone(err));
    BOOST_REQUIRE_EQUAL(err, "LOST");
    BOOST_CHECK(plane.claim_count() == 0);
    BOOST_CHECK(plane.earned_count() == 0);
    BOOST_CHECK_EQUAL(plane.result("task-a"), "receipt-a");
    BOOST_CHECK_EQUAL(plane.head("channel-a"), "head-a");
    BOOST_CHECK_EQUAL(plane.checkpoint(), "ckpt-a");
    BOOST_CHECK(!plane.saved());
    ExpectClosed(plane);
}

BOOST_AUTO_TEST_CASE(permanent_gone_keeps_earned_and_claim)
{
    modelnet::SwarmFaultBoard earned_only;
    std::string err = "prior";
    BOOST_REQUIRE(earned_only.KeepEarned("work-a", 8, err));
    err = "prior";
    BOOST_REQUIRE(!earned_only.PermanentGone(err));
    BOOST_REQUIRE_EQUAL(err, "DURABLE");
    BOOST_CHECK(earned_only.has_earned("work-a"));
    BOOST_CHECK(earned_only.earned("work-a") == 8);
    BOOST_CHECK(earned_only.atoms_moved() == 0);

    modelnet::SwarmFaultBoard both;
    BOOST_REQUIRE(both.KeepClaim("task-a", "worker-a", err));
    BOOST_REQUIRE(both.KeepEarned("work-a", 8, err));
    err = "prior";
    BOOST_REQUIRE(!both.PermanentGone(err));
    BOOST_REQUIRE_EQUAL(err, "DURABLE");
    BOOST_CHECK(both.claim_count() == 1);
    BOOST_CHECK_EQUAL(both.claim("task-a"), "worker-a");
    BOOST_CHECK(both.earned_count() == 1);
    BOOST_CHECK(both.earned("work-a") == 8);

    err = "prior";
    BOOST_REQUIRE(!both.DatasetWithdrawn(err));
    BOOST_REQUIRE(!both.FalseCompat(err));
    BOOST_REQUIRE_EQUAL(err, "FAMILY_NOT_COMPAT");
    BOOST_CHECK(!both.running());
    BOOST_CHECK(!both.admitted());
    BOOST_CHECK(both.earned("work-a") == 8);
    BOOST_CHECK_EQUAL(both.claim("task-a"), "worker-a");
    ExpectClosed(both);
}

BOOST_AUTO_TEST_CASE(revoked_read_and_idle_flags_stay_closed)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.RevokedRead(err));
    BOOST_REQUIRE_EQUAL(err, "NOT_READ");
    BOOST_CHECK(plane.bytes_moved() == 0);
    BOOST_CHECK(!plane.admitted());
    BOOST_CHECK(!plane.running());
    BOOST_CHECK(!plane.qualified());
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(!plane.launched());
    ExpectClosed(plane);
}

BOOST_AUTO_TEST_SUITE_END()
