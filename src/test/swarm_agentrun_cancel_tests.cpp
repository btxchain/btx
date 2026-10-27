// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/swarm_agentrun.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_agentrun_cancel_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_task_is_task_and_stores_nothing)
{
    modelnet::SwarmAgentRun plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Cancel("missing", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE(!plane.cancelled("missing"));
    BOOST_REQUIRE(!plane.cancelled(""));
    BOOST_REQUIRE_EQUAL(plane.task_count(), 0u);
    BOOST_REQUIRE(plane.Trace().empty());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(cancel_sets_the_flag_and_a_second_cancel_is_replay)
{
    modelnet::SwarmAgentRun plane;
    std::string err;

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    BOOST_REQUIRE(plane.AddTask("child", "root", "draft", err));
    BOOST_REQUIRE(!plane.cancelled("child"));

    BOOST_REQUIRE(plane.Cancel("child", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cancelled("child"));
    BOOST_REQUIRE(!plane.cancelled("root"));
    BOOST_REQUIRE_EQUAL(plane.parent_of("child"), "root");
    BOOST_REQUIRE_EQUAL(plane.capability_of("child"), "draft");
    BOOST_REQUIRE_EQUAL(plane.children_of("root").size(), 1u);
    BOOST_REQUIRE(plane.receipt("child").empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Cancel("child", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.cancelled("child"));

    const std::vector<std::string> trace = plane.Trace();
    BOOST_REQUIRE_EQUAL(trace.size(), 3u);
    BOOST_REQUIRE_EQUAL(trace[2], "Cancel");
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(cancel_keeps_a_stored_result_lease_and_branch)
{
    modelnet::SwarmAgentRun plane;
    std::string err;

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    BOOST_REQUIRE(plane.Lease("root", "worker-a", 2, 80, 10, err));
    BOOST_REQUIRE(plane.Assign("root", "worker-a", 2, err));
    BOOST_REQUIRE(plane.CommitResult("root", "receipt-1", err));
    BOOST_REQUIRE(plane.Speculate("branch-1", "root", err));

    BOOST_REQUIRE(plane.Cancel("root", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cancelled("root"));
    BOOST_REQUIRE_EQUAL(plane.receipt("root"), "receipt-1");
    BOOST_REQUIRE(plane.leased("root"));
    BOOST_REQUIRE_EQUAL(plane.lease_worker("root"), "worker-a");
    BOOST_REQUIRE(plane.assigned("root"));
    BOOST_REQUIRE(plane.has_branch("branch-1"));
    BOOST_REQUIRE_EQUAL(plane.branch_count(), 1u);

    err = "prior";
    BOOST_REQUIRE(!plane.CommitResult("root", "receipt-2", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(plane.receipt("root"), "receipt-1");
    BOOST_REQUIRE(plane.cancelled("root"));

    BOOST_REQUIRE(plane.AddTask("child", "root", "draft", err));
    BOOST_REQUIRE(plane.Lease("child", "worker-b", 1, 40, 5, err));
    BOOST_REQUIRE(plane.Assign("child", "worker-b", 1, err));
    BOOST_REQUIRE(plane.Cancel("child", err));
    BOOST_REQUIRE(plane.cancelled("child"));
    BOOST_REQUIRE(plane.receipt("child").empty());
    BOOST_REQUIRE(plane.CommitResult("child", "receipt-child", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.receipt("child"), "receipt-child");
    BOOST_REQUIRE(plane.cancelled("child"));

    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
