// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/limits.h>
#include <modelnet/swarm_natpub/swarm_natpub.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void RequireStill(const modelnet::SwarmNatPublish& plane)
{
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmNatPubBytesMoved);
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(plane.connected() == modelnet::kSwarmNatPubConnected);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmNatPubLaunched);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(plane.published() == modelnet::kSwarmNatPubPublished);
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(static_cast<int64_t>(plane.dns_seeds().size()) == modelnet::kSwarmNatPubSeedCount);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_natpub_bytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bytes_connection_launch_and_seeds_stay_fixed)
{
    modelnet::SwarmNatPublish plane;
    std::string err = "prior";

    RequireStill(plane);

    BOOST_REQUIRE(!plane.Claim("", err));
    BOOST_REQUIRE(err == "ENDPOINT");
    BOOST_REQUIRE(plane.claim_count() == 0);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Claim("ep-a", err));
    BOOST_REQUIRE(err == "HELD");
    BOOST_REQUIRE(plane.claimed("ep-a"));
    BOOST_REQUIRE(plane.stored_endpoint("ep-a") == "ep-a");
    BOOST_REQUIRE(plane.claim_count() == 1);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.published("ep-a"));
    BOOST_REQUIRE(!plane.connected("ep-a"));
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Claim("ep-a", err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(plane.stored_endpoint("ep-a") == "ep-a");
    BOOST_REQUIRE(plane.claim_count() == 1);
    BOOST_REQUIRE(!plane.published());
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Claim("ep-b", err));
    BOOST_REQUIRE(err == "HELD");
    BOOST_REQUIRE(plane.claimed("ep-b"));
    BOOST_REQUIRE(plane.stored_endpoint("ep-b") == "ep-b");
    BOOST_REQUIRE(plane.claim_count() == 2);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.published("ep-b"));
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Claim("", err));
    BOOST_REQUIRE(err == "ENDPOINT");
    BOOST_REQUIRE(plane.stored_endpoint("ep-a") == "ep-a");
    BOOST_REQUIRE(plane.stored_endpoint("ep-b") == "ep-b");
    BOOST_REQUIRE(plane.claim_count() == 2);
    RequireStill(plane);
}

BOOST_AUTO_TEST_SUITE_END()
