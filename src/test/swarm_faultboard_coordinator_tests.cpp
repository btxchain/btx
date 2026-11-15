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
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(plane.bytes_moved() == 0);
    BOOST_CHECK(plane.atoms_moved() == 0);
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
    BOOST_CHECK(!plane.broadcast());
    BOOST_CHECK(!plane.mined());
    BOOST_CHECK(!plane.saved());
    BOOST_CHECK(!plane.qualified());
    BOOST_CHECK(!plane.admitted());
    BOOST_CHECK(!plane.running());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_faultboard_coordinator_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fresh_board_has_no_claim_and_epoch_zero)
{
    modelnet::SwarmFaultBoard plane;
    BOOST_CHECK(plane.claim_count() == 0);
    BOOST_CHECK(!plane.has_claim("task-a"));
    BOOST_CHECK_EQUAL(plane.claim("task-a"), "");
    BOOST_CHECK(plane.epoch() == 0);
    BOOST_CHECK(!plane.frozen());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(coordinator_gone_without_a_claim_is_lost)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.CoordinatorGone(err));
    BOOST_REQUIRE_EQUAL(err, "LOST");
    BOOST_CHECK(plane.claim_count() == 0);
    BOOST_CHECK(plane.earned_count() == 0);
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(keep_claim_is_durable_across_coordinator_gone)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepClaim("task-a", "worker-a", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(plane.KeepClaim("task-b", "worker-b", err));
    BOOST_CHECK(plane.claim_count() == 2);
    BOOST_CHECK(plane.has_claim("task-a"));
    BOOST_CHECK_EQUAL(plane.claim("task-a"), "worker-a");
    BOOST_CHECK_EQUAL(plane.claim("task-b"), "worker-b");

    BOOST_REQUIRE(plane.KeepClaim("task-a", "worker-a", err));
    BOOST_CHECK(plane.claim_count() == 2);

    err = "prior";
    BOOST_REQUIRE(!plane.KeepClaim("task-a", "worker-other", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_CHECK(plane.claim_count() == 2);
    BOOST_CHECK_EQUAL(plane.claim("task-a"), "worker-a");

    err = "prior";
    BOOST_REQUIRE(!plane.CoordinatorGone(err));
    BOOST_REQUIRE_EQUAL(err, "DURABLE");
    BOOST_CHECK(plane.claim_count() == 2);
    BOOST_CHECK_EQUAL(plane.claim("task-a"), "worker-a");
    BOOST_CHECK_EQUAL(plane.claim("task-b"), "worker-b");
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(replace_coordinator_stores_only_a_greater_epoch)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.ReplaceCoordinator(0, 0, err));
    BOOST_REQUIRE_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(plane.epoch() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.ReplaceCoordinator(5, 4, err));
    BOOST_REQUIRE_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(plane.epoch() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.ReplaceCoordinator(2, 2, err));
    BOOST_REQUIRE_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(plane.epoch() == 0);

    BOOST_REQUIRE(plane.ReplaceCoordinator(1, 2, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(plane.epoch() == 2);

    err = "prior";
    BOOST_REQUIRE(!plane.ReplaceCoordinator(2, 2, err));
    BOOST_REQUIRE_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(plane.epoch() == 2);

    BOOST_REQUIRE(plane.ReplaceCoordinator(2, 8, err));
    BOOST_CHECK(plane.epoch() == 8);

    BOOST_REQUIRE(plane.ReplaceCoordinator(0, 3, err));
    BOOST_CHECK(plane.epoch() == 3);
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(resume_stale_commits_nothing)
{
    modelnet::SwarmFaultBoard plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.KeepClaim("task-a", "worker-a", err));
    BOOST_REQUIRE(plane.ReplaceCoordinator(0, 7, err));
    BOOST_CHECK(plane.epoch() == 7);

    err = "prior";
    BOOST_REQUIRE(!plane.ResumeStale(1, 5, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_CHECK(plane.epoch() == 7);
    BOOST_CHECK(plane.claim_count() == 1);
    BOOST_CHECK_EQUAL(plane.claim("task-a"), "worker-a");

    err = "prior";
    BOOST_REQUIRE(plane.ResumeStale(5, 5, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(plane.epoch() == 7);
    BOOST_CHECK(plane.claim_count() == 1);

    err = "prior";
    BOOST_REQUIRE(plane.ResumeStale(6, 5, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(plane.epoch() == 7);
    BOOST_CHECK(plane.earned_count() == 0);
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(permanent_gone_keeps_claim_or_earned)
{
    modelnet::SwarmFaultBoard empty;
    std::string err = "prior";
    BOOST_REQUIRE(!empty.PermanentGone(err));
    BOOST_REQUIRE_EQUAL(err, "LOST");
    BOOST_CHECK(empty.claim_count() == 0);
    BOOST_CHECK(empty.earned_count() == 0);

    modelnet::SwarmFaultBoard claimed;
    BOOST_REQUIRE(claimed.KeepClaim("task-a", "worker-a", err));
    err = "prior";
    BOOST_REQUIRE(!claimed.PermanentGone(err));
    BOOST_REQUIRE_EQUAL(err, "DURABLE");
    BOOST_CHECK(claimed.claim_count() == 1);
    BOOST_CHECK_EQUAL(claimed.claim("task-a"), "worker-a");

    modelnet::SwarmFaultBoard paid;
    BOOST_REQUIRE(paid.KeepEarned("work-a", 9, err));
    err = "prior";
    BOOST_REQUIRE(!paid.PermanentGone(err));
    BOOST_REQUIRE_EQUAL(err, "DURABLE");
    BOOST_CHECK(paid.earned_count() == 1);
    BOOST_CHECK(paid.has_earned("work-a"));
    BOOST_CHECK(paid.earned("work-a") == 9);
    BOOST_CHECK(paid.atoms_moved() == 0);

    modelnet::SwarmFaultBoard result_only;
    BOOST_REQUIRE(result_only.KeepResult("task-a", "receipt-a", err));
    BOOST_REQUIRE(result_only.KeepCheckpoint("ckpt-a", err));
    err = "prior";
    BOOST_REQUIRE(!result_only.PermanentGone(err));
    BOOST_REQUIRE_EQUAL(err, "LOST");
    BOOST_CHECK(result_only.has_result("task-a"));
    BOOST_CHECK_EQUAL(result_only.result("task-a"), "receipt-a");
    BOOST_CHECK_EQUAL(result_only.checkpoint(), "ckpt-a");
    BOOST_CHECK(!result_only.saved());
    ExpectIdle(result_only);
}

BOOST_AUTO_TEST_SUITE_END()
