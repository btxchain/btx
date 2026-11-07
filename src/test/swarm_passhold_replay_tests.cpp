// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_passhold/codes.h>
#include <modelnet/swarm_passhold/limits.h>
#include <modelnet/swarm_passhold/swarm_passhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_passhold_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_request_of_the_same_name_is_replay)
{
    modelnet::SwarmPassHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("pass-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldNotStarted);
    BOOST_REQUIRE_EQUAL(err, "NOT_STARTED");
    BOOST_REQUIRE(plane.requested("pass-1"));
    BOOST_REQUIRE(plane.stored_name("pass-1") == "pass-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.started());
    BOOST_REQUIRE(!plane.passed());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("pass-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.requested("pass-1"));
    BOOST_REQUIRE(plane.stored_name("pass-1") == "pass-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.started());
    BOOST_REQUIRE(plane.started() == modelnet::kSwarmPassHoldStarted);
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE(plane.passed() == modelnet::kSwarmPassHoldPassed);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("pass-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_name("pass-1") == "pass-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.started());
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_name_is_passthrough_before_replay)
{
    modelnet::SwarmPassHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("pass-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldNotStarted);
    BOOST_REQUIRE_EQUAL(err, "NOT_STARTED");

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldPassthrough);
    BOOST_REQUIRE_EQUAL(err, "PASSTHROUGH");
    BOOST_REQUIRE(plane.stored_name("pass-1") == "pass-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.started());
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_when_another_name_is_stored)
{
    modelnet::SwarmPassHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("pass-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldNotStarted);
    BOOST_REQUIRE_EQUAL(err, "NOT_STARTED");

    err = "prior";
    BOOST_REQUIRE(!plane.Request("pass-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldNotStarted);
    BOOST_REQUIRE_EQUAL(err, "NOT_STARTED");

    err = "prior";
    BOOST_REQUIRE(!plane.Request("pass-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.requested("pass-1"));
    BOOST_REQUIRE(plane.requested("pass-2"));
    BOOST_REQUIRE(plane.stored_name("pass-1") == "pass-1");
    BOOST_REQUIRE(plane.stored_name("pass-2") == "pass-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.started());
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmPassHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
