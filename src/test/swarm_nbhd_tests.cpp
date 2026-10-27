// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nbhd.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nbhd_tests, BasicTestingSetup)

static modelnet::SwarmNeighborhood NotedNeighborhood()
{
    modelnet::SwarmNeighborhood neighborhood;
    neighborhood.node_id = "peer-a";
    neighborhood.lowest_rtt = 4;
    neighborhood.new_domains = 2;
    neighborhood.want_connect = false;
    return neighborhood;
}

static void ExpectClosed(const modelnet::SwarmNeighborhoodResult& result)
{
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.socket_opened);
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_peer)
{
    modelnet::SwarmNeighborhood neighborhood = NotedNeighborhood();
    neighborhood.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNeighborhoodResult result = modelnet::SwarmNoteNeighborhood(neighborhood, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(negative_lowest_rtt_is_peer)
{
    modelnet::SwarmNeighborhood neighborhood = NotedNeighborhood();
    neighborhood.lowest_rtt = -1;
    std::string err = "prior";
    const modelnet::SwarmNeighborhoodResult result = modelnet::SwarmNoteNeighborhood(neighborhood, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(negative_new_domains_is_peer)
{
    modelnet::SwarmNeighborhood neighborhood = NotedNeighborhood();
    neighborhood.new_domains = -1;
    std::string err = "prior";
    const modelnet::SwarmNeighborhoodResult result = modelnet::SwarmNoteNeighborhood(neighborhood, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(peer_wins_over_want_connect)
{
    modelnet::SwarmNeighborhood neighborhood = NotedNeighborhood();
    neighborhood.node_id.clear();
    neighborhood.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmNeighborhoodResult result = modelnet::SwarmNoteNeighborhood(neighborhood, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(lowest_rtt_above_four_is_rtt_cap)
{
    modelnet::SwarmNeighborhood neighborhood = NotedNeighborhood();
    neighborhood.lowest_rtt = 5;
    std::string err = "prior";
    const modelnet::SwarmNeighborhoodResult result = modelnet::SwarmNoteNeighborhood(neighborhood, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "RTT_CAP");
    BOOST_CHECK_EQUAL(err, "RTT_CAP");
}

BOOST_AUTO_TEST_CASE(rtt_cap_wins_over_want_connect)
{
    modelnet::SwarmNeighborhood neighborhood = NotedNeighborhood();
    neighborhood.lowest_rtt = 5;
    neighborhood.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmNeighborhoodResult result = modelnet::SwarmNoteNeighborhood(neighborhood, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "RTT_CAP");
    BOOST_CHECK_EQUAL(err, "RTT_CAP");
}

BOOST_AUTO_TEST_CASE(rtt_cap_wins_over_domain_cap)
{
    modelnet::SwarmNeighborhood neighborhood = NotedNeighborhood();
    neighborhood.lowest_rtt = 5;
    neighborhood.new_domains = 3;
    neighborhood.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmNeighborhoodResult result = modelnet::SwarmNoteNeighborhood(neighborhood, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "RTT_CAP");
    BOOST_CHECK_EQUAL(err, "RTT_CAP");
}

BOOST_AUTO_TEST_CASE(new_domains_above_two_is_domain_cap)
{
    modelnet::SwarmNeighborhood neighborhood = NotedNeighborhood();
    neighborhood.new_domains = 3;
    std::string err = "prior";
    const modelnet::SwarmNeighborhoodResult result = modelnet::SwarmNoteNeighborhood(neighborhood, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "DOMAIN_CAP");
    BOOST_CHECK_EQUAL(err, "DOMAIN_CAP");
}

BOOST_AUTO_TEST_CASE(domain_cap_wins_over_want_connect)
{
    modelnet::SwarmNeighborhood neighborhood = NotedNeighborhood();
    neighborhood.new_domains = 3;
    neighborhood.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmNeighborhoodResult result = modelnet::SwarmNoteNeighborhood(neighborhood, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "DOMAIN_CAP");
    BOOST_CHECK_EQUAL(err, "DOMAIN_CAP");
}

BOOST_AUTO_TEST_CASE(want_connect_is_held)
{
    modelnet::SwarmNeighborhood neighborhood = NotedNeighborhood();
    neighborhood.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmNeighborhoodResult result = modelnet::SwarmNoteNeighborhood(neighborhood, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(cap_bounds_with_want_connect_are_held)
{
    modelnet::SwarmNeighborhood neighborhood = NotedNeighborhood();
    neighborhood.lowest_rtt = 4;
    neighborhood.new_domains = 2;
    neighborhood.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmNeighborhoodResult result = modelnet::SwarmNoteNeighborhood(neighborhood, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(within_caps_is_noted)
{
    modelnet::SwarmNeighborhood neighborhood = NotedNeighborhood();
    neighborhood.lowest_rtt = 0;
    neighborhood.new_domains = 0;
    std::string err = "prior";
    const modelnet::SwarmNeighborhoodResult result = modelnet::SwarmNoteNeighborhood(neighborhood, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(lowest_rtt_four_and_new_domains_two_is_noted)
{
    modelnet::SwarmNeighborhood neighborhood = NotedNeighborhood();
    neighborhood.lowest_rtt = 4;
    neighborhood.new_domains = 2;
    neighborhood.want_connect = false;
    std::string err = "prior";
    const modelnet::SwarmNeighborhoodResult result = modelnet::SwarmNoteNeighborhood(neighborhood, err);
    ExpectClosed(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
