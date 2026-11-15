// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_passhold/codes.h>
#include <modelnet/swarm_passhold/limits.h>
#include <modelnet/swarm_passhold/swarm_passhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_passhold_empty_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_request_is_passthrough_and_stores_nothing)
{
    modelnet::SwarmPassHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldPassthrough);
    BOOST_REQUIRE_EQUAL(err, "PASSTHROUGH");
    BOOST_REQUIRE(!plane.requested(""));
    BOOST_REQUIRE(plane.stored_name("").empty());
    BOOST_REQUIRE(plane.request_count() == 0);
    BOOST_REQUIRE(!plane.started());
    BOOST_REQUIRE(plane.started() == modelnet::kSwarmPassHoldStarted);
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE(plane.passed() == modelnet::kSwarmPassHoldPassed);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldPassthrough);
    BOOST_REQUIRE_EQUAL(err, "PASSTHROUGH");
    BOOST_REQUIRE(plane.request_count() == 0);
    BOOST_REQUIRE(!plane.started());
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_name_leaves_a_stored_request_in_place)
{
    modelnet::SwarmPassHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("pass-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldNotStarted);
    BOOST_REQUIRE_EQUAL(err, "NOT_STARTED");
    BOOST_REQUIRE(plane.requested("pass-1"));
    BOOST_REQUIRE(plane.stored_name("pass-1") == "pass-1");
    BOOST_REQUIRE(!plane.started());
    BOOST_REQUIRE(!plane.passed());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldPassthrough);
    BOOST_REQUIRE_EQUAL(err, "PASSTHROUGH");
    BOOST_REQUIRE(plane.requested("pass-1"));
    BOOST_REQUIRE(plane.stored_name("pass-1") == "pass-1");
    BOOST_REQUIRE(!plane.requested(""));
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.started());
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
