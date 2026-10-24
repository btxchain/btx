// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_discover/swarm_discover.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectQuiet(const modelnet::SwarmDiscover& discover)
{
    BOOST_CHECK(!discover.launched());
    BOOST_CHECK(!discover.gpu());
    BOOST_CHECK(!discover.broadcast());
    BOOST_CHECK(!discover.connected());
    BOOST_CHECK_EQUAL(discover.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(discover.bytes_moved(), static_cast<int64_t>(0));
}

void OfferGrant(modelnet::SwarmDiscover& discover, const std::string& peer, const std::string& scope, const std::string& endpoint)
{
    std::string err = "prior";
    BOOST_REQUIRE(discover.Offer(peer, scope, endpoint, 1000, 1, err));
    BOOST_REQUIRE(discover.Grant(peer, scope, err));
    BOOST_CHECK(discover.granted(peer));
}

} // namespace

BOOST_AUTO_TEST_SUITE(swarm_discover_tests)

BOOST_FIXTURE_TEST_CASE(offer_does_not_authorize_use, BasicTestingSetup)
{
    modelnet::SwarmDiscover discover;
    std::string err = "prior";
    BOOST_REQUIRE(discover.Offer("peer-a", "lan", "endpoint-a", 100, 10, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(discover.offered("peer-a"));
    BOOST_CHECK(!discover.granted("peer-a"));
    BOOST_CHECK_EQUAL(discover.endpoint_of("peer-a"), "endpoint-a");

    BOOST_CHECK(!discover.Use("peer-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORIZED");
    BOOST_CHECK(!discover.connected());
    ExpectQuiet(discover);

    BOOST_CHECK(!discover.Offer("peer-a", "wan", "endpoint-b", 200, 10, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(discover.scope_of("peer-a"), "lan");
    BOOST_CHECK_EQUAL(discover.endpoint_of("peer-a"), "endpoint-a");
    BOOST_CHECK(!discover.granted("peer-a"));
    BOOST_CHECK(!discover.Use("peer-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORIZED");
    BOOST_CHECK(!discover.connected());
    ExpectQuiet(discover);
}

BOOST_FIXTURE_TEST_CASE(grant_then_use_leaves_connected_false, BasicTestingSetup)
{
    modelnet::SwarmDiscover discover;
    std::string err = "prior";
    BOOST_REQUIRE(discover.Offer("peer-a", "public", "endpoint-a", 100, 10, err));
    BOOST_REQUIRE(discover.Grant("peer-a", "public", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(discover.granted("peer-a"));

    BOOST_REQUIRE(discover.Use("peer-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!discover.connected());
    BOOST_CHECK_EQUAL(discover.endpoint_of("peer-a"), "endpoint-a");
    ExpectQuiet(discover);
}

BOOST_FIXTURE_TEST_CASE(scan_is_not_scan, BasicTestingSetup)
{
    modelnet::SwarmDiscover discover;
    std::string err = "prior";
    BOOST_REQUIRE(discover.Offer("peer-a", "private", "endpoint-a", 100, 10, err));

    BOOST_CHECK(!discover.Scan("prefix", err));
    BOOST_CHECK_EQUAL(err, "NOT_SCAN");
    BOOST_CHECK(!discover.offered("prefix"));
    BOOST_CHECK_EQUAL(discover.endpoint_of("peer-a"), "endpoint-a");
    BOOST_CHECK_EQUAL(discover.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!discover.connected());
    ExpectQuiet(discover);
}

BOOST_FIXTURE_TEST_CASE(different_grant_does_not_replace_a_faster_route, BasicTestingSetup)
{
    modelnet::SwarmDiscover discover;
    std::string err = "prior";
    OfferGrant(discover, "peer-a", "lan", "endpoint-a");
    OfferGrant(discover, "peer-b", "lan", "endpoint-b");

    BOOST_REQUIRE(discover.Route("object-1", "peer-a", "grant-1", 40, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(discover.route_peer("object-1"), "peer-a");
    BOOST_CHECK_EQUAL(discover.route_grant_id("object-1"), "grant-1");
    BOOST_CHECK_EQUAL(discover.route_rtt_ms("object-1"), static_cast<int64_t>(40));

    BOOST_CHECK(!discover.Route("object-1", "peer-b", "grant-2", 5, err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK_EQUAL(discover.route_peer("object-1"), "peer-a");
    BOOST_CHECK_EQUAL(discover.route_grant_id("object-1"), "grant-1");
    BOOST_CHECK_EQUAL(discover.route_rtt_ms("object-1"), static_cast<int64_t>(40));
    BOOST_CHECK(!discover.connected());
    ExpectQuiet(discover);
}

BOOST_FIXTURE_TEST_CASE(same_grant_lower_rtt_replaces_the_peer, BasicTestingSetup)
{
    modelnet::SwarmDiscover discover;
    std::string err = "prior";
    OfferGrant(discover, "peer-a", "wan", "endpoint-a");
    OfferGrant(discover, "peer-b", "wan", "endpoint-b");

    BOOST_REQUIRE(discover.Route("object-1", "peer-a", "grant-1", 40, err));
    BOOST_REQUIRE(discover.Route("object-1", "peer-b", "grant-1", 9, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(discover.route_peer("object-1"), "peer-b");
    BOOST_CHECK_EQUAL(discover.route_grant_id("object-1"), "grant-1");
    BOOST_CHECK_EQUAL(discover.route_rtt_ms("object-1"), static_cast<int64_t>(9));
    BOOST_CHECK(!discover.connected());
    ExpectQuiet(discover);
}

BOOST_FIXTURE_TEST_CASE(equal_now_and_until_is_expired, BasicTestingSetup)
{
    modelnet::SwarmDiscover discover;
    std::string err = "prior";
    BOOST_CHECK(!discover.Offer("peer-a", "lan", "endpoint-a", 50, 50, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK(!discover.offered("peer-a"));
    BOOST_CHECK(discover.endpoint_of("peer-a").empty());
    BOOST_CHECK(!discover.granted("peer-a"));
    BOOST_CHECK(!discover.connected());
    ExpectQuiet(discover);
}

BOOST_FIXTURE_TEST_CASE(partition_false_is_partition_and_connected_stays_false, BasicTestingSetup)
{
    modelnet::SwarmDiscover discover;
    std::string err = "prior";
    BOOST_REQUIRE(discover.Offer("peer-a", "private", "endpoint-a", 100, 1, err));

    BOOST_CHECK(!discover.Partition(false, err));
    BOOST_CHECK_EQUAL(err, "PARTITION");
    BOOST_CHECK_EQUAL(discover.status(), "PARTITION");
    BOOST_CHECK(!discover.connected());
    BOOST_CHECK_EQUAL(discover.endpoint_of("peer-a"), "endpoint-a");
    BOOST_CHECK(!discover.offered(""));
    ExpectQuiet(discover);

    BOOST_REQUIRE(discover.Partition(true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(discover.status(), "LOCAL");
    BOOST_CHECK(!discover.connected());
    BOOST_CHECK_EQUAL(discover.endpoint_of("peer-a"), "endpoint-a");
    ExpectQuiet(discover);
}

BOOST_FIXTURE_TEST_CASE(automatic_spend_is_zero, BasicTestingSetup)
{
    modelnet::SwarmDiscover discover;
    BOOST_CHECK_EQUAL(discover.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(discover.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!discover.launched());
    BOOST_CHECK(!discover.gpu());
    BOOST_CHECK(!discover.broadcast());
    BOOST_CHECK(!discover.connected());
    ExpectQuiet(discover);
}

BOOST_AUTO_TEST_SUITE_END()
