// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/nodedefault.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nodedefault_cpu_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(raise_above_cap_is_capped)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE_EQUAL(node.cpu_threads(), 64);
    BOOST_REQUIRE(!node.RaiseThreads(65, err));
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE_EQUAL(node.cpu_threads(), 64);
}

BOOST_AUTO_TEST_CASE(raise_below_zero_is_capped)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(!node.RaiseThreads(-1, err));
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE_EQUAL(node.cpu_threads(), 64);
}

BOOST_AUTO_TEST_CASE(raise_inside_cap_leaves_sixty_four)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(node.RaiseThreads(64, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(node.cpu_threads(), 64);

    err = "prior";
    BOOST_REQUIRE(node.RaiseThreads(0, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(node.cpu_threads(), 64);

    err = "prior";
    BOOST_REQUIRE(node.RaiseThreads(63, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(node.cpu_threads(), 64);
}

BOOST_AUTO_TEST_SUITE_END()
