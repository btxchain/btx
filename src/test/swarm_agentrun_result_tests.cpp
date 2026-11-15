// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/swarm_agentrun.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_agentrun_result_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(assign_without_a_matching_lease_is_fence)
{
    modelnet::SwarmAgentRun plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Assign("missing", "worker-a", 1, err));
    BOOST_REQUIRE_EQUAL(err, "FENCE");
    BOOST_REQUIRE(!plane.assigned("missing"));
    BOOST_REQUIRE(plane.Trace().empty());

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    err = "prior";
    BOOST_REQUIRE(!plane.Assign("root", "worker-a", 1, err));
    BOOST_REQUIRE_EQUAL(err, "FENCE");
    BOOST_REQUIRE(!plane.assigned("root"));

    BOOST_REQUIRE(plane.Lease("root", "worker-a", 1, 5000, 1000, err));
    err = "prior";
    BOOST_REQUIRE(!plane.Assign("root", "worker-b", 1, err));
    BOOST_REQUIRE_EQUAL(err, "FENCE");
    err = "prior";
    BOOST_REQUIRE(!plane.Assign("root", "worker-a", 2, err));
    BOOST_REQUIRE_EQUAL(err, "FENCE");
    BOOST_REQUIRE(!plane.assigned("root"));
    BOOST_REQUIRE(plane.assigned_worker("root").empty());
    BOOST_REQUIRE_EQUAL(plane.assigned_epoch("root"), 0);
    BOOST_REQUIRE_EQUAL(plane.Trace().size(), 2u);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(matching_assign_is_stored_once)
{
    modelnet::SwarmAgentRun plane;
    std::string err;

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    BOOST_REQUIRE(plane.Lease("root", "worker-a", 4, 9, 1, err));
    BOOST_REQUIRE(plane.Assign("root", "worker-a", 4, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.assigned("root"));
    BOOST_REQUIRE_EQUAL(plane.assigned_worker("root"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.assigned_epoch("root"), 4);
    BOOST_REQUIRE(plane.receipt("root").empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Assign("root", "worker-a", 4, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.assigned_worker("root"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.assigned_epoch("root"), 4);

    err = "prior";
    BOOST_REQUIRE(!plane.Assign("root", "worker-b", 4, err));
    BOOST_REQUIRE_EQUAL(err, "FENCE");
    BOOST_REQUIRE_EQUAL(plane.assigned_worker("root"), "worker-a");

    const std::vector<std::string> trace = plane.Trace();
    BOOST_REQUIRE_EQUAL(trace.size(), 3u);
    BOOST_REQUIRE_EQUAL(trace[2], "Assign");
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(empty_receipt_and_unassigned_task_store_nothing)
{
    modelnet::SwarmAgentRun plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.CommitResult("missing", "", err));
    BOOST_REQUIRE_EQUAL(err, "RECEIPT");
    BOOST_REQUIRE(plane.receipt("missing").empty());

    err = "prior";
    BOOST_REQUIRE(!plane.CommitResult("missing", "receipt-1", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_ASSIGNED");

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    err = "prior";
    BOOST_REQUIRE(!plane.CommitResult("root", "", err));
    BOOST_REQUIRE_EQUAL(err, "RECEIPT");
    err = "prior";
    BOOST_REQUIRE(!plane.CommitResult("root", "receipt-1", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_ASSIGNED");
    BOOST_REQUIRE(plane.receipt("root").empty());
    BOOST_REQUIRE(!plane.assigned("root"));

    BOOST_REQUIRE(plane.Lease("root", "worker-a", 1, 20, 10, err));
    err = "prior";
    BOOST_REQUIRE(!plane.CommitResult("root", "receipt-1", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_ASSIGNED");
    BOOST_REQUIRE(plane.receipt("root").empty());
    BOOST_REQUIRE_EQUAL(plane.Trace().size(), 2u);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(first_receipt_stays_across_replay_and_conflict)
{
    modelnet::SwarmAgentRun plane;
    std::string err;

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    BOOST_REQUIRE(plane.AddTask("child", "root", "draft", err));
    BOOST_REQUIRE(plane.Lease("child", "worker-a", 3, 100, 1, err));
    BOOST_REQUIRE(plane.Assign("child", "worker-a", 3, err));

    BOOST_REQUIRE(plane.CommitResult("child", "receipt-1", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.receipt("child"), "receipt-1");
    BOOST_REQUIRE(plane.receipt("root").empty());

    err = "prior";
    BOOST_REQUIRE(!plane.CommitResult("child", "receipt-1", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.receipt("child"), "receipt-1");

    err = "prior";
    BOOST_REQUIRE(!plane.CommitResult("child", "receipt-2", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(plane.receipt("child"), "receipt-1");
    BOOST_REQUIRE_EQUAL(plane.assigned_worker("child"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.assigned_epoch("child"), 3);

    const std::vector<std::string> trace = plane.Trace();
    BOOST_REQUIRE_EQUAL(trace.size(), 5u);
    BOOST_REQUIRE_EQUAL(trace[3], "Assign");
    BOOST_REQUIRE_EQUAL(trace[4], "CommitResult");
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
