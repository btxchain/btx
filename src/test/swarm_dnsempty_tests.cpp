// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dnsempty.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_dnsempty_tests, BasicTestingSetup)

static modelnet::SwarmDnsSeeds NotedSeeds()
{
    modelnet::SwarmDnsSeeds seeds;
    seeds.node_id = "node-1";
    seeds.requested_seeds = 0;
    seeds.want_publish = false;
    return seeds;
}

static void ExpectUnpublished(const modelnet::SwarmDnsSeedsResult& result)
{
    BOOST_CHECK_EQUAL(result.seed_count, 0);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.socket_opened);
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_dns)
{
    modelnet::SwarmDnsSeeds seeds = NotedSeeds();
    seeds.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmDnsSeedsResult result = modelnet::SwarmNoteDnsSeeds(seeds, err);
    ExpectUnpublished(result);
    BOOST_CHECK_EQUAL(result.code, "DNS");
    BOOST_CHECK_EQUAL(err, "DNS");
}

BOOST_AUTO_TEST_CASE(empty_node_id_wins_over_publish_and_requested_seeds)
{
    modelnet::SwarmDnsSeeds seeds = NotedSeeds();
    seeds.node_id.clear();
    seeds.requested_seeds = 3;
    seeds.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmDnsSeedsResult result = modelnet::SwarmNoteDnsSeeds(seeds, err);
    ExpectUnpublished(result);
    BOOST_CHECK_EQUAL(result.code, "DNS");
    BOOST_CHECK_EQUAL(err, "DNS");
}

BOOST_AUTO_TEST_CASE(negative_requested_seeds_is_dns)
{
    modelnet::SwarmDnsSeeds seeds = NotedSeeds();
    seeds.requested_seeds = -1;
    std::string err = "prior";
    const modelnet::SwarmDnsSeedsResult result = modelnet::SwarmNoteDnsSeeds(seeds, err);
    ExpectUnpublished(result);
    BOOST_CHECK_EQUAL(result.code, "DNS");
    BOOST_CHECK_EQUAL(err, "DNS");
}

BOOST_AUTO_TEST_CASE(negative_requested_seeds_wins_over_want_publish)
{
    modelnet::SwarmDnsSeeds seeds = NotedSeeds();
    seeds.requested_seeds = -1;
    seeds.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmDnsSeedsResult result = modelnet::SwarmNoteDnsSeeds(seeds, err);
    ExpectUnpublished(result);
    BOOST_CHECK_EQUAL(result.code, "DNS");
    BOOST_CHECK_EQUAL(err, "DNS");
}

BOOST_AUTO_TEST_CASE(want_publish_is_empty)
{
    modelnet::SwarmDnsSeeds seeds = NotedSeeds();
    seeds.requested_seeds = 0;
    seeds.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmDnsSeedsResult result = modelnet::SwarmNoteDnsSeeds(seeds, err);
    ExpectUnpublished(result);
    BOOST_CHECK_EQUAL(result.code, "EMPTY");
    BOOST_CHECK_EQUAL(err, "EMPTY");
}

BOOST_AUTO_TEST_CASE(requested_seeds_above_zero_is_empty)
{
    modelnet::SwarmDnsSeeds seeds = NotedSeeds();
    seeds.requested_seeds = 1;
    seeds.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmDnsSeedsResult result = modelnet::SwarmNoteDnsSeeds(seeds, err);
    ExpectUnpublished(result);
    BOOST_CHECK_EQUAL(result.code, "EMPTY");
    BOOST_CHECK_EQUAL(err, "EMPTY");
}

BOOST_AUTO_TEST_CASE(empty_wins_when_want_publish_is_true)
{
    modelnet::SwarmDnsSeeds seeds = NotedSeeds();
    seeds.requested_seeds = 2;
    seeds.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmDnsSeedsResult result = modelnet::SwarmNoteDnsSeeds(seeds, err);
    ExpectUnpublished(result);
    BOOST_CHECK_EQUAL(result.code, "EMPTY");
    BOOST_CHECK_EQUAL(err, "EMPTY");
}

BOOST_AUTO_TEST_CASE(zero_requested_seeds_without_publish_is_noted)
{
    modelnet::SwarmDnsSeeds seeds = NotedSeeds();
    seeds.requested_seeds = 0;
    seeds.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmDnsSeedsResult result = modelnet::SwarmNoteDnsSeeds(seeds, err);
    ExpectUnpublished(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
