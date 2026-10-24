// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/swarm_agentrun.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_agentrun_leader_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(no_lease_is_lost_and_deletes_nothing)
{
    modelnet::SwarmAgentRun plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.LeaderGone(err));
    BOOST_REQUIRE_EQUAL(err, "LOST");
    BOOST_REQUIRE_EQUAL(plane.task_count(), 0u);
    BOOST_REQUIRE(plane.Trace().empty());

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    BOOST_REQUIRE(plane.AddTask("child", "root", "draft", err));
    err = "prior";
    BOOST_REQUIRE(!plane.LeaderGone(err));
    BOOST_REQUIRE_EQUAL(err, "LOST");
    BOOST_REQUIRE_EQUAL(plane.task_count(), 2u);
    BOOST_REQUIRE_EQUAL(plane.parent_of("child"), "root");
    BOOST_REQUIRE_EQUAL(plane.capability_of("child"), "draft");
    BOOST_REQUIRE(!plane.leased("root"));
    BOOST_REQUIRE(!plane.leased("child"));
    BOOST_REQUIRE(plane.receipt("child").empty());

    const std::vector<std::string> trace = plane.Trace();
    BOOST_REQUIRE_EQUAL(trace.size(), 2u);
    BOOST_REQUIRE_EQUAL(trace[0], "AddTask");
    BOOST_REQUIRE_EQUAL(trace[1], "AddTask");
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(any_lease_is_durable_and_keeps_leases_and_results)
{
    modelnet::SwarmAgentRun plane;
    std::string err;

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    BOOST_REQUIRE(plane.AddTask("left", "root", "draft", err));
    BOOST_REQUIRE(plane.AddTask("right", "root", "review", err));
    BOOST_REQUIRE(plane.Lease("left", "worker-a", 1, 5000, 1000, err));
    BOOST_REQUIRE(plane.Assign("left", "worker-a", 1, err));
    BOOST_REQUIRE(plane.CommitResult("left", "receipt-1", err));

    const std::size_t before = plane.Trace().size();
    err = "prior";
    BOOST_REQUIRE(!plane.LeaderGone(err));
    BOOST_REQUIRE_EQUAL(err, "DURABLE");
    BOOST_REQUIRE(!plane.LeaderGone(err));
    BOOST_REQUIRE_EQUAL(err, "DURABLE");

    BOOST_REQUIRE(plane.leased("left"));
    BOOST_REQUIRE_EQUAL(plane.lease_worker("left"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.lease_epoch("left"), 1);
    BOOST_REQUIRE_EQUAL(plane.lease_until_ms("left"), 5000);
    BOOST_REQUIRE_EQUAL(plane.lease_now_ms("left"), 1000);
    BOOST_REQUIRE(!plane.leased("right"));
    BOOST_REQUIRE(plane.assigned("left"));
    BOOST_REQUIRE_EQUAL(plane.receipt("left"), "receipt-1");
    BOOST_REQUIRE_EQUAL(plane.task_count(), 3u);
    BOOST_REQUIRE_EQUAL(plane.children_of("root").size(), 2u);
    BOOST_REQUIRE_EQUAL(plane.Trace().size(), before);
    BOOST_REQUIRE(!plane.cancelled("left"));
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
