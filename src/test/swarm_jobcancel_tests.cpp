// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_jobcancel.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_jobcancel_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cancel_before_finish)
{
    modelnet::SwarmJobCancel jobs;
    std::string err = "prior";
    BOOST_CHECK(!jobs.Open("", err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_CHECK(jobs.Open("task-a", err));
    BOOST_CHECK(err.empty());
    err = "prior";
    BOOST_CHECK(!jobs.Open("task-a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");

    err = "prior";
    BOOST_CHECK(jobs.Cancel("task-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(jobs.cancelled("task-a"));
    BOOST_CHECK(jobs.result("task-a").empty());

    err = "prior";
    BOOST_CHECK(!jobs.Finish("task-a", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "CANCELLED");
    BOOST_CHECK(jobs.cancelled("task-a"));
    BOOST_CHECK(jobs.result("task-a").empty());

    err = "prior";
    BOOST_CHECK(jobs.Cancel("task-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(jobs.cancelled("task-a"));
}

BOOST_AUTO_TEST_CASE(finish_blocks_cancel)
{
    modelnet::SwarmJobCancel jobs;
    std::string err = "prior";
    BOOST_CHECK(!jobs.Finish("missing", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_CHECK(!jobs.Cancel("missing", err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_CHECK(!jobs.cancelled("missing"));
    BOOST_CHECK(jobs.result("missing").empty());

    BOOST_CHECK(jobs.Open("task-b", err));
    err = "prior";
    BOOST_CHECK(!jobs.Finish("task-b", "", err));
    BOOST_CHECK_EQUAL(err, "HASH");
    BOOST_CHECK(jobs.result("task-b").empty());
    BOOST_CHECK(!jobs.cancelled("task-b"));

    err = "prior";
    BOOST_CHECK(jobs.Finish("task-b", "hash-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(jobs.result("task-b"), "hash-b");
    BOOST_CHECK(!jobs.cancelled("task-b"));

    err = "prior";
    BOOST_CHECK(jobs.Finish("task-b", "hash-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(jobs.result("task-b"), "hash-b");

    err = "prior";
    BOOST_CHECK(!jobs.Cancel("task-b", err));
    BOOST_CHECK_EQUAL(err, "FINISHED");
    BOOST_CHECK_EQUAL(jobs.result("task-b"), "hash-b");
    BOOST_CHECK(!jobs.cancelled("task-b"));
}

BOOST_AUTO_TEST_CASE(conflict)
{
    modelnet::SwarmJobCancel jobs;
    std::string err = "prior";
    BOOST_CHECK(jobs.Open("task-c", err));
    BOOST_CHECK(jobs.Finish("task-c", "hash-c", err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!jobs.Finish("task-c", "hash-other", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(jobs.result("task-c"), "hash-c");
    BOOST_CHECK(!jobs.cancelled("task-c"));

    err = "prior";
    BOOST_CHECK(jobs.Finish("task-c", "hash-c", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(jobs.result("task-c"), "hash-c");

    err = "prior";
    BOOST_CHECK(!jobs.Cancel("task-c", err));
    BOOST_CHECK_EQUAL(err, "FINISHED");
    BOOST_CHECK_EQUAL(jobs.result("task-c"), "hash-c");
}

BOOST_AUTO_TEST_SUITE_END()
