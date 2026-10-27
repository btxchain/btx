// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_loginhold/codes.h>
#include <modelnet/swarm_loginhold/limits.h>
#include <modelnet/swarm_loginhold/swarm_loginhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_loginhold_request_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_request_stays_logged_out)
{
    modelnet::SwarmLoginHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.requested("op-a"));
    BOOST_REQUIRE(plane.stored_name("op-a").empty());
    BOOST_REQUIRE(plane.request_count() == 0);
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(!plane.Request("op-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLoginHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("op-a"));
    BOOST_REQUIRE(plane.stored_name("op-a") == "op-a");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE(plane.logged_in() == modelnet::kSwarmLoginHoldLoggedIn);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmLoginHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmLoginHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmLoginHoldLaunched);
}

BOOST_AUTO_TEST_CASE(a_second_distinct_name_is_stored_beside_the_first)
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
    BOOST_REQUIRE(!plane.Request("op-b", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLoginHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("op-a"));
    BOOST_REQUIRE(plane.requested("op-b"));
    BOOST_REQUIRE(plane.stored_name("op-a") == "op-a");
    BOOST_REQUIRE(plane.stored_name("op-b") == "op-b");
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(space_and_code_word_are_stored_and_stay_logged_out)
{
    modelnet::SwarmLoginHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request(" ", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLoginHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested(" "));
    BOOST_REQUIRE(plane.stored_name(" ") == " ");
    BOOST_REQUIRE(!plane.logged_in());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("LOGIN", err));
    BOOST_REQUIRE(err == modelnet::kSwarmLoginHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("LOGIN"));
    BOOST_REQUIRE(plane.stored_name("LOGIN") == "LOGIN");
    BOOST_REQUIRE(plane.requested(" "));
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.logged_in());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
