// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_passhold/codes.h>
#include <modelnet/swarm_passhold/limits.h>
#include <modelnet/swarm_passhold/swarm_passhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_passhold_request_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_request_stays_unstarted)
{
    modelnet::SwarmPassHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.requested("pass-1"));
    BOOST_REQUIRE(plane.stored_name("pass-1").empty());
    BOOST_REQUIRE(plane.request_count() == 0);
    BOOST_REQUIRE(!plane.started());
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(!plane.Request("pass-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldNotStarted);
    BOOST_REQUIRE_EQUAL(err, "NOT_STARTED");
    BOOST_REQUIRE(plane.requested("pass-1"));
    BOOST_REQUIRE(plane.stored_name("pass-1") == "pass-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.started());
    BOOST_REQUIRE(plane.started() == modelnet::kSwarmPassHoldStarted);
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE(plane.passed() == modelnet::kSwarmPassHoldPassed);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmPassHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmPassHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmPassHoldLaunched);
}

BOOST_AUTO_TEST_CASE(a_second_distinct_name_is_stored_beside_the_first)
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
    BOOST_REQUIRE(!plane.Request("pass-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldNotStarted);
    BOOST_REQUIRE_EQUAL(err, "NOT_STARTED");
    BOOST_REQUIRE(plane.requested("pass-1"));
    BOOST_REQUIRE(plane.requested("pass-2"));
    BOOST_REQUIRE(plane.stored_name("pass-1") == "pass-1");
    BOOST_REQUIRE(plane.stored_name("pass-2") == "pass-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.started());
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(space_and_code_word_are_stored_and_stay_unstarted)
{
    modelnet::SwarmPassHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request(" ", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldNotStarted);
    BOOST_REQUIRE_EQUAL(err, "NOT_STARTED");
    BOOST_REQUIRE(plane.requested(" "));
    BOOST_REQUIRE(plane.stored_name(" ") == " ");
    BOOST_REQUIRE(!plane.started());
    BOOST_REQUIRE(!plane.passed());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("PASSTHROUGH", err));
    BOOST_REQUIRE(err == modelnet::kSwarmPassHoldNotStarted);
    BOOST_REQUIRE_EQUAL(err, "NOT_STARTED");
    BOOST_REQUIRE(plane.requested("PASSTHROUGH"));
    BOOST_REQUIRE(plane.stored_name("PASSTHROUGH") == "PASSTHROUGH");
    BOOST_REQUIRE(plane.requested(" "));
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.started());
    BOOST_REQUIRE(!plane.passed());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
