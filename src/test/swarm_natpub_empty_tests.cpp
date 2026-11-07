// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/swarm_natpub.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_natpub_empty_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_endpoint_is_endpoint_and_stores_nothing)
{
    modelnet::SwarmNatPublish plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Claim("", err));
    BOOST_REQUIRE(err == "ENDPOINT");
    BOOST_REQUIRE(!plane.claimed(""));
    BOOST_REQUIRE(plane.stored_endpoint("").empty());
    BOOST_REQUIRE(plane.claim_count() == 0);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.published(""));
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(plane.dns_seeds().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Claim("", err));
    BOOST_REQUIRE(err == "ENDPOINT");
    BOOST_REQUIRE(plane.claim_count() == 0);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(plane.dns_seeds().empty());
}

BOOST_AUTO_TEST_CASE(empty_endpoint_leaves_a_stored_claim_in_place)
{
    modelnet::SwarmNatPublish plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Claim("ep-a", err));
    BOOST_REQUIRE(err == "HELD");
    BOOST_REQUIRE(plane.claimed("ep-a"));
    BOOST_REQUIRE(plane.stored_endpoint("ep-a") == "ep-a");
    BOOST_REQUIRE(!plane.published());

    err = "prior";
    BOOST_REQUIRE(!plane.Claim("", err));
    BOOST_REQUIRE(err == "ENDPOINT");
    BOOST_REQUIRE(plane.claimed("ep-a"));
    BOOST_REQUIRE(plane.stored_endpoint("ep-a") == "ep-a");
    BOOST_REQUIRE(!plane.claimed(""));
    BOOST_REQUIRE(plane.claim_count() == 1);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.published("ep-a"));
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(plane.dns_seeds().empty());
}

BOOST_AUTO_TEST_SUITE_END()
