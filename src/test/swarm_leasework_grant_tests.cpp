// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/swarm_leasework.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_leasework_grant_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(epoch_starts_at_one_and_nothing_is_launched)
{
    modelnet::SwarmLeaseWork plane;
    BOOST_REQUIRE_EQUAL(plane.epoch(), 1);
    BOOST_REQUIRE(plane.leader().empty());
    BOOST_REQUIRE(!plane.commit_right());
    BOOST_REQUIRE_EQUAL(plane.grants(), 0u);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(empty_task_or_worker_is_task_and_stores_nothing)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Grant("", "worker-a", 1000, 5000, err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE(!plane.has(""));
    BOOST_REQUIRE_EQUAL(plane.grants(), 0u);

    err = "prior";
    BOOST_REQUIRE(!plane.Grant("task-1", "", 1000, 5000, err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE(!plane.has("task-1"));

    err = "prior";
    BOOST_REQUIRE(!plane.Grant("", "", 1000, 5000, err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE_EQUAL(plane.grants(), 0u);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(negative_bound_is_range_and_stores_nothing)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Grant("task-1", "worker-a", -1, 5000, err));
    BOOST_REQUIRE_EQUAL(err, "RANGE");
    BOOST_REQUIRE(!plane.has("task-1"));

    err = "prior";
    BOOST_REQUIRE(!plane.Grant("task-1", "worker-a", 1000, -1, err));
    BOOST_REQUIRE_EQUAL(err, "RANGE");
    BOOST_REQUIRE(!plane.has("task-1"));

    err = "prior";
    BOOST_REQUIRE(!plane.Grant("task-1", "worker-a", -5, -1, err));
    BOOST_REQUIRE_EQUAL(err, "RANGE");

    err = "prior";
    BOOST_REQUIRE(!plane.Grant("task-1", "worker-a", std::numeric_limits<int64_t>::min(), 10, err));
    BOOST_REQUIRE_EQUAL(err, "RANGE");
    BOOST_REQUIRE_EQUAL(plane.grants(), 0u);
    BOOST_REQUIRE(!plane.live("worker-a"));
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(duplicate_task_is_replay_and_keeps_the_first_worker)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Grant("task-1", "worker-a", 1000, 5000, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.has("task-1"));
    BOOST_REQUIRE_EQUAL(plane.worker("task-1"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.grant_epoch("task-1"), 1);
    BOOST_REQUIRE_EQUAL(plane.until_ms("task-1"), 5000);
    BOOST_REQUIRE(plane.live("worker-a"));
    BOOST_REQUIRE(!plane.committed("task-1"));
    BOOST_REQUIRE_EQUAL(plane.grants(), 1u);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(plane.Grant("task-2", "worker-b", 1000, 4000, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.grants(), 2u);
    BOOST_REQUIRE_EQUAL(plane.worker("task-2"), "worker-b");

    err = "prior";
    BOOST_REQUIRE(!plane.Grant("task-1", "worker-b", 1000, 9000, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.worker("task-1"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.grant_epoch("task-1"), 1);
    BOOST_REQUIRE_EQUAL(plane.until_ms("task-1"), 5000);
    BOOST_REQUIRE_EQUAL(plane.grants(), 2u);
    BOOST_REQUIRE(!plane.live(""));
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
