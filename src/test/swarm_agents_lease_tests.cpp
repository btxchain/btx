// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/plane.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_agents_lease_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(epoch_starts_at_one_and_a_stale_epoch_cannot_commit)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE_EQUAL(plane.epoch(), 1);
    BOOST_CHECK(!plane.admitted());

    BOOST_CHECK(!plane.Grant("", 10, 10, err));
    BOOST_CHECK_EQUAL(err, "LEASE");
    BOOST_CHECK(!plane.admitted());
    BOOST_REQUIRE_EQUAL(plane.epoch(), 1);

    err = "prior";
    BOOST_CHECK(!plane.Grant("L", 9, 10, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK(!plane.admitted());
    BOOST_REQUIRE_EQUAL(plane.epoch(), 1);
    BOOST_CHECK(plane.lease_id().empty());
    BOOST_CHECK_EQUAL(plane.lease_until(), 0);

    BOOST_REQUIRE(plane.Add("a", {}, err));
    err = "prior";
    BOOST_CHECK(!plane.CommitEpoch(0, "a", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(plane.CommittedHash("a").empty());
    BOOST_REQUIRE(plane.Trace().empty());

    err = "prior";
    BOOST_CHECK(!plane.CommitEpoch(2, "a", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(plane.CommittedHash("a").empty());
    BOOST_REQUIRE(plane.Trace().empty());
}

BOOST_AUTO_TEST_CASE(inclusive_expiry_starts_at_epoch_one)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Add("a", {}, err));
    BOOST_REQUIRE_EQUAL(plane.epoch(), 1);
    BOOST_REQUIRE(plane.Grant("L", 10, 10, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.admitted());
    BOOST_REQUIRE_EQUAL(plane.epoch(), 1);
    BOOST_REQUIRE_EQUAL(plane.lease_id(), "L");
    BOOST_REQUIRE_EQUAL(plane.lease_until(), 10);

    BOOST_REQUIRE(plane.CommitEpoch(1, "a", "hash-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.CommittedHash("a"), "hash-a");

    err = "prior";
    BOOST_CHECK(!plane.CommitEpoch(0, "a", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_REQUIRE_EQUAL(plane.CommittedHash("a"), "hash-a");
}

BOOST_AUTO_TEST_CASE(expired_grant_keeps_the_admitted_lease_and_epoch)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Add("a", {}, err));
    BOOST_REQUIRE(plane.Add("b", {}, err));
    BOOST_REQUIRE(plane.Grant("L", 10, 10, err));
    BOOST_REQUIRE_EQUAL(plane.epoch(), 1);

    err = "prior";
    BOOST_CHECK(!plane.Grant("L2", 11, 12, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_REQUIRE(plane.admitted());
    BOOST_REQUIRE_EQUAL(plane.epoch(), 1);
    BOOST_REQUIRE_EQUAL(plane.lease_id(), "L");
    BOOST_REQUIRE_EQUAL(plane.lease_until(), 10);

    BOOST_REQUIRE(plane.Grant("L2", 30, 12, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.epoch(), 1);
    BOOST_REQUIRE_EQUAL(plane.lease_id(), "L2");
    BOOST_REQUIRE_EQUAL(plane.lease_until(), 30);

    err = "prior";
    BOOST_CHECK(!plane.CommitEpoch(2, "a", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(plane.CommittedHash("a").empty());
    BOOST_REQUIRE(plane.Trace().empty());

    BOOST_REQUIRE(plane.CommitEpoch(1, "a", "hash-a", err));
    BOOST_REQUIRE_EQUAL(plane.CommittedHash("a"), "hash-a");

    BOOST_REQUIRE(plane.CommitEpoch(1, "b", "hash-b", err));
    BOOST_REQUIRE_EQUAL(plane.CommittedHash("b"), "hash-b");

    err = "prior";
    BOOST_CHECK(!plane.CommitEpoch(1, "b", "hash-other", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(plane.CommittedHash("b"), "hash-b");
}

BOOST_AUTO_TEST_SUITE_END()
