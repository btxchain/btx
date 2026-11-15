// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_neighbor.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_neighbor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNeighbor neighbor{"", 2, 1, false};
    std::string err;
    const modelnet::SwarmNeighborResult result = modelnet::SwarmCapNeighborhood(neighbor, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
    BOOST_CHECK_EQUAL(result.kept_rtt, 0);
    BOOST_CHECK_EQUAL(result.kept_domains, 0);
}

BOOST_AUTO_TEST_CASE(negative_lowest_rtt_is_range)
{
    modelnet::SwarmNeighbor neighbor{"n1", -1, 1, false};
    std::string err;
    const modelnet::SwarmNeighborResult result = modelnet::SwarmCapNeighborhood(neighbor, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.code, "RANGE");
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(result.kept_rtt, 0);
    BOOST_CHECK_EQUAL(result.kept_domains, 0);
}

BOOST_AUTO_TEST_CASE(over_cap_is_capped)
{
    modelnet::SwarmNeighbor neighbor{"n1", 6, 3, false};
    std::string err;
    const modelnet::SwarmNeighborResult result = modelnet::SwarmCapNeighborhood(neighbor, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK_EQUAL(result.kept_rtt, 4);
    BOOST_CHECK_EQUAL(result.kept_domains, 2);
}

BOOST_AUTO_TEST_CASE(want_connect_is_held)
{
    modelnet::SwarmNeighbor neighbor{"n1", 2, 1, true};
    std::string err;
    const modelnet::SwarmNeighborResult result = modelnet::SwarmCapNeighborhood(neighbor, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(result.kept_rtt, 2);
    BOOST_CHECK_EQUAL(result.kept_domains, 1);
}

BOOST_AUTO_TEST_CASE(inside_cap_is_noted)
{
    modelnet::SwarmNeighbor neighbor{"n1", 2, 1, false};
    std::string err = "stale";
    const modelnet::SwarmNeighborResult result = modelnet::SwarmCapNeighborhood(neighbor, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(result.kept_rtt, 2);
    BOOST_CHECK_EQUAL(result.kept_domains, 1);
}

BOOST_AUTO_TEST_SUITE_END()
