// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/plane.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_agents_account_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(charge_adds_both_totals_per_agent)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_CHECK(!plane.Charge("", 1, 1, err));
    BOOST_CHECK_EQUAL(err, "AGENT");
    BOOST_CHECK_EQUAL(plane.Threads(""), 0);
    BOOST_CHECK_EQUAL(plane.Memory(""), 0);

    BOOST_CHECK(!plane.Charge("alpha", -1, 8, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK(!plane.Charge("alpha", 1, -8, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(plane.Threads("alpha"), 0);
    BOOST_CHECK_EQUAL(plane.Memory("alpha"), 0);

    BOOST_REQUIRE(plane.Charge("alpha", 4, 512, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.Threads("alpha"), 4);
    BOOST_REQUIRE_EQUAL(plane.Memory("alpha"), 512);

    BOOST_REQUIRE(plane.Charge("alpha", 2, 128, err));
    BOOST_REQUIRE_EQUAL(plane.Threads("alpha"), 6);
    BOOST_REQUIRE_EQUAL(plane.Memory("alpha"), 640);
    BOOST_CHECK_EQUAL(plane.Threads("beta"), 0);
    BOOST_CHECK_EQUAL(plane.Memory("beta"), 0);
}

BOOST_AUTO_TEST_CASE(charge_past_the_cap_adds_nothing)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Charge("alpha", 40, 1000, err));
    BOOST_REQUIRE(err.empty());

    BOOST_CHECK(!plane.Charge("alpha", 25, 1, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK_EQUAL(plane.Threads("alpha"), 40);
    BOOST_CHECK_EQUAL(plane.Memory("alpha"), 1000);

    BOOST_CHECK(!plane.Charge("alpha", 1, 16000, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK_EQUAL(plane.Threads("alpha"), 40);
    BOOST_CHECK_EQUAL(plane.Memory("alpha"), 1000);

    BOOST_CHECK(!plane.Charge("gamma", 65, 0, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK_EQUAL(plane.Threads("gamma"), 0);
    BOOST_CHECK_EQUAL(plane.Memory("gamma"), 0);

    BOOST_CHECK(!plane.Charge("gamma", 0, 16385, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK_EQUAL(plane.Threads("gamma"), 0);

    BOOST_REQUIRE(plane.Charge("alpha", 24, 15384, err));
    BOOST_REQUIRE_EQUAL(plane.Threads("alpha"), 64);
    BOOST_REQUIRE_EQUAL(plane.Memory("alpha"), 16384);

    BOOST_CHECK(!plane.Charge("alpha", 1, 0, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK(!plane.Charge("alpha", 0, 1, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_REQUIRE_EQUAL(plane.Threads("alpha"), 64);
    BOOST_REQUIRE_EQUAL(plane.Memory("alpha"), 16384);

    BOOST_REQUIRE(plane.Charge("beta", 64, 16384, err));
    BOOST_REQUIRE_EQUAL(plane.Threads("beta"), 64);
    BOOST_REQUIRE_EQUAL(plane.Memory("beta"), 16384);
    BOOST_REQUIRE_EQUAL(plane.Threads("alpha"), 64);
}

BOOST_AUTO_TEST_CASE(release_above_the_total_is_range)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Charge("alpha", 10, 1000, err));

    BOOST_CHECK(!plane.Release("alpha", 11, 1, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(plane.Threads("alpha"), 10);
    BOOST_CHECK_EQUAL(plane.Memory("alpha"), 1000);

    BOOST_CHECK(!plane.Release("alpha", 1, 1001, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(plane.Threads("alpha"), 10);
    BOOST_CHECK_EQUAL(plane.Memory("alpha"), 1000);

    BOOST_CHECK(!plane.Release("alpha", -1, 1, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(plane.Threads("alpha"), 10);
    BOOST_CHECK_EQUAL(plane.Memory("alpha"), 1000);

    BOOST_CHECK(!plane.Release("missing", 1, 0, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(plane.Threads("missing"), 0);

    BOOST_REQUIRE(plane.Release("alpha", 4, 250, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.Threads("alpha"), 6);
    BOOST_REQUIRE_EQUAL(plane.Memory("alpha"), 750);

    BOOST_REQUIRE(plane.Release("alpha", 6, 750, err));
    BOOST_REQUIRE_EQUAL(plane.Threads("alpha"), 0);
    BOOST_REQUIRE_EQUAL(plane.Memory("alpha"), 0);

    BOOST_CHECK(!plane.Release("alpha", 1, 0, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(plane.Threads("alpha"), 0);
    BOOST_CHECK_EQUAL(plane.Memory("alpha"), 0);
}

BOOST_AUTO_TEST_SUITE_END()
