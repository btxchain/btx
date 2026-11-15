// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_loginhold/codes.h>
#include <modelnet/swarm_loginhold/limits.h>
#include <modelnet/swarm_loginhold/swarm_loginhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_loginhold_empty_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_request_is_login_and_stores_nothing)
{
    modelnet::SwarmLoginHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLoginHoldLogin);
    BOOST_REQUIRE_EQUAL(err, "LOGIN");
    BOOST_REQUIRE(!plane.requested(""));
    BOOST_REQUIRE(plane.stored_name("").empty());
    BOOST_REQUIRE(plane.request_count() == 0);
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE(plane.logged_in() == modelnet::kSwarmLoginHoldLoggedIn);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLoginHoldLogin);
    BOOST_REQUIRE_EQUAL(err, "LOGIN");
    BOOST_REQUIRE(plane.request_count() == 0);
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_name_leaves_a_stored_request_in_place)
{
    modelnet::SwarmLoginHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("op-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLoginHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("op-a"));
    BOOST_REQUIRE(plane.stored_name("op-a") == "op-a");
    BOOST_REQUIRE(!plane.logged_in());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLoginHoldLogin);
    BOOST_REQUIRE_EQUAL(err, "LOGIN");
    BOOST_REQUIRE(plane.requested("op-a"));
    BOOST_REQUIRE(plane.stored_name("op-a") == "op-a");
    BOOST_REQUIRE(!plane.requested(""));
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
