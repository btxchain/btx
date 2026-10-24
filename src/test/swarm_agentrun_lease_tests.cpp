// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/swarm_agentrun.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_agentrun_lease_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_task_is_task_before_worker_epoch_and_expiry)
{
    modelnet::SwarmAgentRun plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Lease("missing", "", -1, 1, 5, err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE(!plane.leased("missing"));
    BOOST_REQUIRE(plane.lease_worker("missing").empty());
    BOOST_REQUIRE_EQUAL(plane.lease_epoch("missing"), 0);
    BOOST_REQUIRE(plane.Trace().empty());

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    err = "prior";
    BOOST_REQUIRE(!plane.Lease("", "worker-a", 1, 10, 1, err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE_EQUAL(plane.task_count(), 1u);
    BOOST_REQUIRE(!plane.leased("root"));
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_worker_is_worker_before_epoch)
{
    modelnet::SwarmAgentRun plane;
    std::string err;

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    err = "prior";
    BOOST_REQUIRE(!plane.Lease("root", "", -5, 1, 9, err));
    BOOST_REQUIRE_EQUAL(err, "WORKER");
    BOOST_REQUIRE(!plane.leased("root"));
    BOOST_REQUIRE(plane.Trace().size() == 1u);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
}

BOOST_AUTO_TEST_CASE(negative_epoch_is_epoch_before_expiry)
{
    modelnet::SwarmAgentRun plane;
    std::string err;

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    err = "prior";
    BOOST_REQUIRE(!plane.Lease("root", "worker-a", -1, 1, 5, err));
    BOOST_REQUIRE_EQUAL(err, "EPOCH");
    BOOST_REQUIRE(!plane.leased("root"));

    err = "prior";
    BOOST_REQUIRE(!plane.Lease("root", "worker-a", -1, 10, 1, err));
    BOOST_REQUIRE_EQUAL(err, "EPOCH");
    BOOST_REQUIRE_EQUAL(plane.Trace().size(), 1u);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(now_at_or_after_until_is_expired_and_stores_nothing)
{
    modelnet::SwarmAgentRun plane;
    std::string err;

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));

    err = "prior";
    BOOST_REQUIRE(!plane.Lease("root", "worker-a", 0, 5, 5, err));
    BOOST_REQUIRE_EQUAL(err, "EXPIRED");
    BOOST_REQUIRE(!plane.leased("root"));

    err = "prior";
    BOOST_REQUIRE(!plane.Lease("root", "worker-a", 1, 4, 5, err));
    BOOST_REQUIRE_EQUAL(err, "EXPIRED");
    BOOST_REQUIRE(!plane.leased("root"));
    BOOST_REQUIRE_EQUAL(plane.lease_until_ms("root"), 0);
    BOOST_REQUIRE_EQUAL(plane.lease_now_ms("root"), 0);
    BOOST_REQUIRE_EQUAL(plane.Trace().size(), 1u);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(valid_lease_is_stored_and_a_second_lease_is_replay)
{
    modelnet::SwarmAgentRun plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    BOOST_REQUIRE(plane.AddTask("child", "root", "draft", err));

    BOOST_REQUIRE(plane.Lease("child", "worker-a", 0, 6, 5, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.leased("child"));
    BOOST_REQUIRE(!plane.leased("root"));
    BOOST_REQUIRE_EQUAL(plane.lease_worker("child"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.lease_epoch("child"), 0);
    BOOST_REQUIRE_EQUAL(plane.lease_until_ms("child"), 6);
    BOOST_REQUIRE_EQUAL(plane.lease_now_ms("child"), 5);

    BOOST_REQUIRE(plane.Lease("root", "worker-b", 2, -5, -10, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.lease_worker("root"), "worker-b");
    BOOST_REQUIRE_EQUAL(plane.lease_epoch("root"), 2);
    BOOST_REQUIRE_EQUAL(plane.lease_until_ms("root"), -5);
    BOOST_REQUIRE_EQUAL(plane.lease_now_ms("root"), -10);

    err = "prior";
    BOOST_REQUIRE(!plane.Lease("child", "worker-b", 9, 50, 1, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.lease_worker("child"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.lease_epoch("child"), 0);
    BOOST_REQUIRE_EQUAL(plane.lease_until_ms("child"), 6);
    BOOST_REQUIRE_EQUAL(plane.lease_now_ms("child"), 5);

    err = "prior";
    BOOST_REQUIRE(!plane.Lease("child", "", 1, 50, 1, err));
    BOOST_REQUIRE_EQUAL(err, "WORKER");
    BOOST_REQUIRE_EQUAL(plane.lease_worker("child"), "worker-a");

    const std::vector<std::string> trace = plane.Trace();
    BOOST_REQUIRE_EQUAL(trace.size(), 4u);
    BOOST_REQUIRE_EQUAL(trace[0], "AddTask");
    BOOST_REQUIRE_EQUAL(trace[1], "AddTask");
    BOOST_REQUIRE_EQUAL(trace[2], "Lease");
    BOOST_REQUIRE_EQUAL(trace[3], "Lease");
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
