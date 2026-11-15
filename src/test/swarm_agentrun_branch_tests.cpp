// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/swarm_agentrun.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_agentrun_branch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_branch_and_unknown_task_store_nothing)
{
    modelnet::SwarmAgentRun plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Speculate("", "missing", err));
    BOOST_REQUIRE_EQUAL(err, "BRANCH");
    BOOST_REQUIRE_EQUAL(plane.branch_count(), 0u);
    BOOST_REQUIRE(!plane.has_branch(""));

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    err = "prior";
    BOOST_REQUIRE(!plane.Speculate("", "root", err));
    BOOST_REQUIRE_EQUAL(err, "BRANCH");
    BOOST_REQUIRE_EQUAL(plane.branch_count(), 0u);

    err = "prior";
    BOOST_REQUIRE(!plane.Speculate("branch-1", "missing", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE(!plane.has_branch("branch-1"));
    BOOST_REQUIRE(plane.branch_task("branch-1").empty());
    BOOST_REQUIRE_EQUAL(plane.Trace().size(), 1u);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(speculate_keeps_the_branch_when_the_task_has_no_result)
{
    modelnet::SwarmAgentRun plane;
    std::string err;

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    BOOST_REQUIRE(plane.Speculate("branch-1", "root", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.branch_count(), 1u);
    BOOST_REQUIRE(plane.has_branch("branch-1"));
    BOOST_REQUIRE_EQUAL(plane.branch_task("branch-1"), "root");
    BOOST_REQUIRE(plane.receipt("root").empty());

    BOOST_REQUIRE(plane.Speculate("branch-2", "root", err));
    BOOST_REQUIRE_EQUAL(plane.branch_count(), 2u);
    BOOST_REQUIRE_EQUAL(plane.branch_task("branch-2"), "root");

    err = "prior";
    BOOST_REQUIRE(!plane.Speculate("branch-1", "root", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.branch_task("branch-1"), "root");
    BOOST_REQUIRE_EQUAL(plane.branch_count(), 2u);

    err = "prior";
    BOOST_REQUIRE(!plane.Reconcile("missing", err));
    BOOST_REQUIRE_EQUAL(err, "BRANCH");
    BOOST_REQUIRE_EQUAL(plane.branch_count(), 2u);

    BOOST_REQUIRE(plane.Reconcile("branch-1", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.has_branch("branch-1"));
    BOOST_REQUIRE_EQUAL(plane.branch_count(), 2u);
    BOOST_REQUIRE(plane.receipt("root").empty());

    const std::vector<std::string> trace = plane.Trace();
    BOOST_REQUIRE_EQUAL(trace.size(), 3u);
    BOOST_REQUIRE_EQUAL(trace[1], "Speculate");
    BOOST_REQUIRE_EQUAL(trace[2], "Speculate");
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(reconcile_drops_a_branch_whose_task_already_has_a_result)
{
    modelnet::SwarmAgentRun plane;
    std::string err;

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    BOOST_REQUIRE(plane.Lease("root", "worker-a", 1, 50, 10, err));
    BOOST_REQUIRE(plane.Assign("root", "worker-a", 1, err));
    BOOST_REQUIRE(plane.CommitResult("root", "receipt-1", err));
    BOOST_REQUIRE(plane.Speculate("branch-1", "root", err));
    BOOST_REQUIRE_EQUAL(plane.receipt("root"), "receipt-1");
    BOOST_REQUIRE_EQUAL(plane.branch_count(), 1u);

    BOOST_REQUIRE(plane.Speculate("branch-2", "root", err));
    err = "prior";
    BOOST_REQUIRE(!plane.Reconcile("branch-1", err));
    BOOST_REQUIRE_EQUAL(err, "DROPPED");
    BOOST_REQUIRE(!plane.has_branch("branch-1"));
    BOOST_REQUIRE(plane.has_branch("branch-2"));
    BOOST_REQUIRE_EQUAL(plane.branch_count(), 1u);
    BOOST_REQUIRE_EQUAL(plane.receipt("root"), "receipt-1");

    err = "prior";
    BOOST_REQUIRE(!plane.Reconcile("branch-1", err));
    BOOST_REQUIRE_EQUAL(err, "BRANCH");
    BOOST_REQUIRE_EQUAL(plane.receipt("root"), "receipt-1");

    err = "prior";
    BOOST_REQUIRE(!plane.Reconcile("branch-2", err));
    BOOST_REQUIRE_EQUAL(err, "DROPPED");
    BOOST_REQUIRE_EQUAL(plane.branch_count(), 0u);
    BOOST_REQUIRE_EQUAL(plane.receipt("root"), "receipt-1");

    const std::vector<std::string> trace = plane.Trace();
    BOOST_REQUIRE_EQUAL(trace.size(), 6u);
    BOOST_REQUIRE_EQUAL(trace[4], "Speculate");
    BOOST_REQUIRE_EQUAL(trace[5], "Speculate");
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
