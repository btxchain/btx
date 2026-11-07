// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/swarm_agentrun.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_agentrun_sandbox_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(run_is_sandbox_absent_and_stays_unlaunched)
{
    modelnet::SwarmAgentRun plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Run(err));
    BOOST_REQUIRE_EQUAL(err, "SANDBOX_ABSENT");
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.task_count(), 0u);

    BOOST_REQUIRE(!plane.Run(err));
    BOOST_REQUIRE_EQUAL(err, "SANDBOX_ABSENT");
    BOOST_REQUIRE(!plane.launched());

    const std::vector<std::string> trace = plane.Trace();
    BOOST_REQUIRE_EQUAL(trace.size(), 2u);
    BOOST_REQUIRE_EQUAL(trace[0], "SANDBOX_ABSENT");
    BOOST_REQUIRE_EQUAL(trace[1], "SANDBOX_ABSENT");
}

BOOST_AUTO_TEST_CASE(one_plane_covers_dag_lease_result_branch_tool_cancel_and_run)
{
    modelnet::SwarmAgentRun plane;
    std::string err;

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    BOOST_REQUIRE(plane.AddTask("left", "root", "draft", err));
    BOOST_REQUIRE(plane.AddTask("right", "root", "review", err));
    BOOST_REQUIRE_EQUAL(plane.task_count(), 3u);
    BOOST_REQUIRE(plane.parent_of("root").empty());
    BOOST_REQUIRE_EQUAL(plane.parent_of("left"), "root");
    BOOST_REQUIRE_EQUAL(plane.parent_of("right"), "root");
    const std::vector<std::string> children = plane.children_of("root");
    BOOST_REQUIRE_EQUAL(children.size(), 2u);
    BOOST_REQUIRE_EQUAL(children[0], "left");
    BOOST_REQUIRE_EQUAL(children[1], "right");

    BOOST_REQUIRE(plane.Lease("left", "worker-a", 1, 5000, 1000, err));
    BOOST_REQUIRE(plane.leased("left"));
    BOOST_REQUIRE_EQUAL(plane.lease_worker("left"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.lease_epoch("left"), 1);

    BOOST_REQUIRE(plane.Assign("left", "worker-a", 1, err));
    BOOST_REQUIRE(plane.assigned("left"));

    BOOST_REQUIRE(plane.CommitResult("left", "receipt-1", err));
    BOOST_REQUIRE_EQUAL(plane.receipt("left"), "receipt-1");

    err = "prior";
    BOOST_REQUIRE(!plane.CommitResult("left", "receipt-2", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(plane.receipt("left"), "receipt-1");

    BOOST_REQUIRE(plane.Speculate("branch-1", "left", err));
    BOOST_REQUIRE_EQUAL(plane.branch_count(), 1u);
    BOOST_REQUIRE_EQUAL(plane.branch_task("branch-1"), "left");
    BOOST_REQUIRE_EQUAL(plane.receipt("left"), "receipt-1");

    err = "prior";
    BOOST_REQUIRE(!plane.Reconcile("branch-1", err));
    BOOST_REQUIRE_EQUAL(err, "DROPPED");
    BOOST_REQUIRE_EQUAL(plane.branch_count(), 0u);
    BOOST_REQUIRE(!plane.has_branch("branch-1"));
    BOOST_REQUIRE_EQUAL(plane.receipt("left"), "receipt-1");

    err = "prior";
    BOOST_REQUIRE(!plane.ReuseTool("digest-priv", true, err));
    BOOST_REQUIRE_EQUAL(err, "PRIVATE_DATA");
    BOOST_REQUIRE_EQUAL(plane.tool_count(), 0u);
    BOOST_REQUIRE(!plane.tool("digest-priv"));

    err = "prior";
    BOOST_REQUIRE(!plane.LeaderGone(err));
    BOOST_REQUIRE_EQUAL(err, "DURABLE");
    BOOST_REQUIRE(plane.leased("left"));
    BOOST_REQUIRE_EQUAL(plane.receipt("left"), "receipt-1");

    BOOST_REQUIRE(plane.Cancel("left", err));
    BOOST_REQUIRE(plane.cancelled("left"));
    BOOST_REQUIRE_EQUAL(plane.receipt("left"), "receipt-1");
    BOOST_REQUIRE(plane.assigned("left"));

    err = "prior";
    BOOST_REQUIRE(!plane.Run(err));
    BOOST_REQUIRE_EQUAL(err, "SANDBOX_ABSENT");
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.task_count(), 3u);
    BOOST_REQUIRE_EQUAL(plane.receipt("left"), "receipt-1");

    const std::vector<std::string> trace = plane.Trace();
    const std::vector<std::string> want = {
        "AddTask", "AddTask", "AddTask", "Lease", "Assign", "CommitResult", "Speculate", "Cancel", "SANDBOX_ABSENT",
    };
    BOOST_REQUIRE_EQUAL(trace.size(), want.size());
    for (std::size_t i = 0; i < want.size(); ++i) {
        BOOST_REQUIRE_EQUAL(trace[i], want[i]);
    }
}

BOOST_AUTO_TEST_SUITE_END()
