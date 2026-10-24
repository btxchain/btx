// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/swarm_leasework.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_leasework_expiry_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(until_equal_now_is_inclusive_and_stores_the_grant)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Grant("task-1", "worker-a", 1000, 1000, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.has("task-1"));
    BOOST_REQUIRE_EQUAL(plane.worker("task-1"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.until_ms("task-1"), 1000);
    BOOST_REQUIRE_EQUAL(plane.grant_epoch("task-1"), 1);
    BOOST_REQUIRE(plane.live("worker-a"));
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(plane.Grant("task-same", "worker-b", 1000, 1000, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.live("worker-a"));
    BOOST_REQUIRE(plane.live("worker-b"));

    modelnet::SwarmLeaseWork zero;
    BOOST_REQUIRE(zero.Grant("task-0", "worker-z", 0, 0, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(zero.has("task-0"));
    BOOST_REQUIRE(zero.live("worker-z"));
    BOOST_REQUIRE_EQUAL(zero.bytes_moved(), 0);
    BOOST_REQUIRE(!zero.launched());

    modelnet::SwarmLeaseWork top;
    const int64_t kMax = std::numeric_limits<int64_t>::max();
    BOOST_REQUIRE(top.Grant("task-max", "worker-m", kMax, kMax, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(top.has("task-max"));
    BOOST_REQUIRE_EQUAL(top.until_ms("task-max"), kMax);
    BOOST_REQUIRE(top.live("worker-m"));
    BOOST_REQUIRE(!top.broadcast());
}

BOOST_AUTO_TEST_CASE(until_before_now_is_expired_and_stores_nothing)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Grant("task-1", "worker-a", 1000, 999, err));
    BOOST_REQUIRE_EQUAL(err, "EXPIRED");
    BOOST_REQUIRE(!plane.has("task-1"));
    BOOST_REQUIRE(!plane.live("worker-a"));
    BOOST_REQUIRE_EQUAL(plane.grants(), 0u);
    BOOST_REQUIRE(plane.worker("task-1").empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Grant("task-1", "worker-a", 1000, 0, err));
    BOOST_REQUIRE_EQUAL(err, "EXPIRED");
    BOOST_REQUIRE(!plane.has("task-1"));

    BOOST_REQUIRE(!plane.Commit("task-1", 1, "hash-a", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE(!plane.committed("task-1"));

    BOOST_REQUIRE(!plane.ClaimLeader("worker-a", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE(!plane.commit_right());
    BOOST_REQUIRE(plane.leader().empty());

    BOOST_REQUIRE(plane.Grant("task-1", "worker-a", 1000, 1000, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.has("task-1"));
    BOOST_REQUIRE_EQUAL(plane.worker("task-1"), "worker-a");
    BOOST_REQUIRE(plane.live("worker-a"));
    BOOST_REQUIRE_EQUAL(plane.grants(), 1u);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(a_later_clock_expires_an_inclusive_grant)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Grant("early", "worker-a", 1000, 1000, err));
    BOOST_REQUIRE(plane.live("worker-a"));

    BOOST_REQUIRE(plane.Grant("later", "worker-b", 1000, 5000, err));
    BOOST_REQUIRE(plane.live("worker-a"));
    BOOST_REQUIRE(plane.live("worker-b"));

    BOOST_REQUIRE(plane.Grant("after", "worker-c", 1001, 5000, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!plane.live("worker-a"));
    BOOST_REQUIRE(plane.live("worker-b"));
    BOOST_REQUIRE(plane.live("worker-c"));
    BOOST_REQUIRE(plane.has("early"));
    BOOST_REQUIRE_EQUAL(plane.worker("early"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.grants(), 3u);

    err = "prior";
    BOOST_REQUIRE(!plane.ClaimLeader("worker-a", err));
    BOOST_REQUIRE_EQUAL(err, "EXPIRED");
    BOOST_REQUIRE(!plane.commit_right());
    BOOST_REQUIRE(plane.leader().empty());

    BOOST_REQUIRE(plane.ClaimLeader("worker-c", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.leader(), "worker-c");
    BOOST_REQUIRE(plane.commit_right());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(range_and_expired_do_not_replace_a_stored_worker)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Grant("task-1", "worker-a", 10, 20, err));

    err = "prior";
    BOOST_REQUIRE(!plane.Grant("task-1", "worker-b", 30, 10, err));
    BOOST_REQUIRE_EQUAL(err, "EXPIRED");
    BOOST_REQUIRE_EQUAL(plane.worker("task-1"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.until_ms("task-1"), 20);

    err = "prior";
    BOOST_REQUIRE(!plane.Grant("task-1", "worker-b", -1, 20, err));
    BOOST_REQUIRE_EQUAL(err, "RANGE");
    BOOST_REQUIRE_EQUAL(plane.worker("task-1"), "worker-a");

    err = "prior";
    BOOST_REQUIRE(!plane.Grant("task-1", "worker-b", 10, 20, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.worker("task-1"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.grants(), 1u);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
