// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/plane.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_agents_trace_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_event_is_trace_and_stores_nothing)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_CHECK(!plane.Append("task-a", "", err));
    BOOST_CHECK_EQUAL(err, "TRACE");
    BOOST_REQUIRE(plane.Trace().empty());

    err = "prior";
    BOOST_CHECK(!plane.Append("", "note", err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_REQUIRE(plane.Trace().empty());
}

BOOST_AUTO_TEST_CASE(cancel_and_commit_append_rows_in_order)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Add("a", {}, err));
    BOOST_REQUIRE(plane.Add("b", {"a"}, err));
    BOOST_REQUIRE(plane.Add("c", {"b"}, err));

    BOOST_REQUIRE(plane.Commit("a", "hash-a", err));
    BOOST_REQUIRE(plane.Cancel("b", err));

    err = "prior";
    BOOST_CHECK(!plane.Commit("b", "hash-b", err));
    BOOST_CHECK_EQUAL(err, "CANCELLED");

    err = "prior";
    BOOST_CHECK(!plane.Commit("c", "hash-c", err));
    BOOST_CHECK_EQUAL(err, "NOT_READY");

    err = "prior";
    BOOST_REQUIRE(plane.Append("a", "note", err));
    BOOST_REQUIRE(err.empty());

    const std::vector<modelnet::SwarmAgentTraceRow> rows = plane.Trace();
    BOOST_REQUIRE_EQUAL(rows.size(), 3);
    BOOST_REQUIRE_EQUAL(rows[0].task, "a");
    BOOST_REQUIRE_EQUAL(rows[0].event, "commit");
    BOOST_REQUIRE_EQUAL(rows[1].task, "b");
    BOOST_REQUIRE_EQUAL(rows[1].event, "cancel");
    BOOST_REQUIRE_EQUAL(rows[2].task, "a");
    BOOST_REQUIRE_EQUAL(rows[2].event, "note");

    err = "prior";
    BOOST_REQUIRE(plane.Commit("a", "hash-a", err));
    const std::vector<modelnet::SwarmAgentTraceRow> again = plane.Trace();
    BOOST_REQUIRE_EQUAL(again.size(), 4);
    BOOST_REQUIRE_EQUAL(again[3].task, "a");
    BOOST_REQUIRE_EQUAL(again[3].event, "commit");
    BOOST_REQUIRE_EQUAL(plane.CommittedHash("a"), "hash-a");
}

BOOST_AUTO_TEST_CASE(failed_commit_does_not_append)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Add("a", {}, err));
    BOOST_REQUIRE(plane.Commit("a", "hash-a", err));

    err = "prior";
    BOOST_CHECK(!plane.Commit("a", "hash-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");

    err = "prior";
    BOOST_CHECK(!plane.Cancel("missing", err));
    BOOST_CHECK_EQUAL(err, "TASK");

    const std::vector<modelnet::SwarmAgentTraceRow> rows = plane.Trace();
    BOOST_REQUIRE_EQUAL(rows.size(), 1);
    BOOST_REQUIRE_EQUAL(rows[0].task, "a");
    BOOST_REQUIRE_EQUAL(rows[0].event, "commit");
}

BOOST_AUTO_TEST_SUITE_END()
