// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/limits.h>
#include <modelnet/swarm_natpub/swarm_natpub.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_natpub_claim_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(claimed_endpoint_is_stored_and_stays_unpublished)
{
    modelnet::SwarmNatPublish plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.claimed("ep-a"));
    BOOST_REQUIRE(plane.stored_endpoint("ep-a").empty());
    BOOST_REQUIRE(plane.claim_count() == 0);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.published("ep-a"));

    BOOST_REQUIRE(!plane.Claim("ep-a", err));
    BOOST_REQUIRE(err == "HELD");
    BOOST_REQUIRE(plane.claimed("ep-a"));
    BOOST_REQUIRE(plane.stored_endpoint("ep-a") == "ep-a");
    BOOST_REQUIRE(plane.claim_count() == 1);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.published("ep-a"));
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(!plane.connected("ep-a"));
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.published() == modelnet::kSwarmNatPubPublished);
}

BOOST_AUTO_TEST_CASE(a_second_distinct_endpoint_is_held_beside_the_first)
{
    modelnet::SwarmNatPublish plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Claim("ep-a", err));
    BOOST_REQUIRE(err == "HELD");
    BOOST_REQUIRE(plane.claimed("ep-a"));
    BOOST_REQUIRE(plane.stored_endpoint("ep-a") == "ep-a");

    err = "prior";
    BOOST_REQUIRE(!plane.Claim("ep-b", err));
    BOOST_REQUIRE(err == "HELD");
    BOOST_REQUIRE(plane.claimed("ep-a"));
    BOOST_REQUIRE(plane.claimed("ep-b"));
    BOOST_REQUIRE(plane.stored_endpoint("ep-a") == "ep-a");
    BOOST_REQUIRE(plane.stored_endpoint("ep-b") == "ep-b");
    BOOST_REQUIRE(plane.claim_count() == 2);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.published("ep-a"));
    BOOST_REQUIRE(!plane.published("ep-b"));
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(plane.dns_seeds().empty());
}

BOOST_AUTO_TEST_SUITE_END()
