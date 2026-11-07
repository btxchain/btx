// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/plane.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_agents_shared_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(first_hash_wins_and_a_different_hash_conflicts)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_CHECK(!plane.Publish("", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "HASH");
    BOOST_CHECK(plane.Shared("").empty());

    err = "prior";
    BOOST_CHECK(!plane.Publish("job", "", err));
    BOOST_CHECK_EQUAL(err, "HASH");
    BOOST_CHECK(plane.Shared("job").empty());

    BOOST_REQUIRE(plane.Publish("job", "hash-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.Shared("job"), "hash-a");

    err = "prior";
    BOOST_REQUIRE(plane.Publish("job", "hash-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.Shared("job"), "hash-a");

    err = "prior";
    BOOST_CHECK(!plane.Publish("job", "hash-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(plane.Shared("job"), "hash-a");

    BOOST_REQUIRE(plane.Publish("other", "hash-b", err));
    BOOST_REQUIRE_EQUAL(plane.Shared("other"), "hash-b");
    BOOST_REQUIRE_EQUAL(plane.Shared("job"), "hash-a");
}

BOOST_AUTO_TEST_CASE(attach_requires_the_same_hash)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Publish("job", "hash-a", err));

    err = "prior";
    BOOST_CHECK(!plane.Attach("", "job", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "CONSUMER");
    BOOST_CHECK(!plane.attached("", "job"));

    err = "prior";
    BOOST_CHECK(!plane.Attach("reader", "missing", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK(!plane.attached("reader", "missing"));
    BOOST_CHECK(plane.Shared("missing").empty());

    err = "prior";
    BOOST_CHECK(!plane.Attach("reader", "job", "hash-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK(!plane.attached("reader", "job"));
    BOOST_REQUIRE_EQUAL(plane.Shared("job"), "hash-a");

    BOOST_REQUIRE(plane.Attach("reader", "job", "hash-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.attached("reader", "job"));
    BOOST_REQUIRE(!plane.attached("other", "job"));

    err = "prior";
    BOOST_REQUIRE(plane.Attach("reader", "job", "hash-a", err));
    BOOST_REQUIRE(plane.attached("reader", "job"));

    err = "prior";
    BOOST_CHECK(!plane.Publish("job", "hash-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(plane.Shared("job"), "hash-a");
    BOOST_REQUIRE(plane.attached("reader", "job"));
}

BOOST_AUTO_TEST_SUITE_END()
