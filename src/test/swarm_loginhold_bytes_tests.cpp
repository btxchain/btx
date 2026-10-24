// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_loginhold/codes.h>
#include <modelnet/swarm_loginhold/limits.h>
#include <modelnet/swarm_loginhold/swarm_loginhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void RequireStill(const modelnet::SwarmLoginHold& plane)
{
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmLoginHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmLoginHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmLoginHoldLaunched);
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE(plane.logged_in() == modelnet::kSwarmLoginHoldLoggedIn);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_loginhold_bytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bytes_stay_zero)
{
    modelnet::SwarmLoginHold plane;
    std::string err = "prior";

    RequireStill(plane);

    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLoginHoldLogin);
    BOOST_REQUIRE_EQUAL(err, "LOGIN");
    BOOST_REQUIRE(plane.request_count() == 0);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("op-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLoginHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("op-a"));
    BOOST_REQUIRE(plane.stored_name("op-a") == "op-a");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.logged_in());
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("op-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLoginHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_name("op-a") == "op-a");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.logged_in());
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("op-b", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLoginHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored_name("op-b") == "op-b");
    BOOST_REQUIRE(plane.request_count() == 2);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLoginHoldLogin);
    BOOST_REQUIRE_EQUAL(err, "LOGIN");
    BOOST_REQUIRE(plane.stored_name("op-a") == "op-a");
    BOOST_REQUIRE(plane.stored_name("op-b") == "op-b");
    BOOST_REQUIRE(plane.request_count() == 2);
    RequireStill(plane);
}

BOOST_AUTO_TEST_SUITE_END()
