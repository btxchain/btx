// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_trace.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_trace_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_task_or_event_is_trace)
{
    modelnet::SwarmTrace trace;
    std::string err = "prior";
    BOOST_CHECK(!trace.Append("", "opened", err));
    BOOST_CHECK_EQUAL(err, "TRACE");
    BOOST_CHECK_EQUAL(trace.size(), std::size_t{0});
    BOOST_CHECK(trace.Events("").empty());

    err = "prior";
    BOOST_CHECK(!trace.Append("task-a", "", err));
    BOOST_CHECK_EQUAL(err, "TRACE");
    BOOST_CHECK_EQUAL(trace.size(), std::size_t{0});

    err = "prior";
    BOOST_CHECK(!trace.Append("", "", err));
    BOOST_CHECK_EQUAL(err, "TRACE");
    BOOST_CHECK_EQUAL(trace.size(), std::size_t{0});
    BOOST_CHECK(trace.Events("task-a").empty());
}

BOOST_AUTO_TEST_CASE(two_events_stay_in_append_order)
{
    modelnet::SwarmTrace trace;
    std::string err = "prior";
    BOOST_CHECK(trace.Append("task-a", "opened", err));
    BOOST_CHECK(err.empty());
    err = "prior";
    BOOST_CHECK(trace.Append("task-a", "closed", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(trace.size(), std::size_t{2});

    const std::vector<std::string> events = trace.Events("task-a");
    BOOST_REQUIRE_EQUAL(events.size(), 2U);
    BOOST_CHECK_EQUAL(events[0], "opened");
    BOOST_CHECK_EQUAL(events[1], "closed");

    err = "prior";
    BOOST_CHECK(!trace.Append("task-a", "", err));
    BOOST_CHECK_EQUAL(err, "TRACE");
    BOOST_CHECK_EQUAL(trace.size(), std::size_t{2});
    const std::vector<std::string> after = trace.Events("task-a");
    BOOST_REQUIRE_EQUAL(after.size(), 2U);
    BOOST_CHECK_EQUAL(after[0], "opened");
    BOOST_CHECK_EQUAL(after[1], "closed");
}

BOOST_AUTO_TEST_CASE(second_task_does_not_mix_events)
{
    modelnet::SwarmTrace trace;
    std::string err = "prior";
    BOOST_CHECK(trace.Append("task-a", "opened", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(trace.Append("task-b", "noted", err));
    BOOST_CHECK(trace.Append("task-a", "closed", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(trace.size(), std::size_t{3});

    const std::vector<std::string> task_a = trace.Events("task-a");
    const std::vector<std::string> task_b = trace.Events("task-b");
    BOOST_REQUIRE_EQUAL(task_a.size(), 2U);
    BOOST_CHECK_EQUAL(task_a[0], "opened");
    BOOST_CHECK_EQUAL(task_a[1], "closed");
    BOOST_REQUIRE_EQUAL(task_b.size(), 1U);
    BOOST_CHECK_EQUAL(task_b[0], "noted");
    BOOST_CHECK(trace.Events("task-c").empty());
}

BOOST_AUTO_TEST_SUITE_END()
