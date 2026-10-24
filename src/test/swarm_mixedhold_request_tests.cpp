// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mixedhold/codes.h>
#include <modelnet/swarm_mixedhold/limits.h>
#include <modelnet/swarm_mixedhold/swarm_mixedhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_mixedhold_request_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_request_stays_stopped)
{
    modelnet::SwarmMixedHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.requested("mix-1"));
    BOOST_REQUIRE(plane.stored_name("mix-1").empty());
    BOOST_REQUIRE(plane.request_count() == 0);
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE(plane.running() == modelnet::kSwarmMixedHoldRunning);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(!plane.Request("mix-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmMixedHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("mix-1"));
    BOOST_REQUIRE(plane.stored_name("mix-1") == "mix-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE(plane.running() == modelnet::kSwarmMixedHoldRunning);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmMixedHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmMixedHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmMixedHoldLaunched);
}

BOOST_AUTO_TEST_CASE(a_second_distinct_name_is_stored_beside_the_first)
{
    modelnet::SwarmMixedHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("mix-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmMixedHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("mix-1"));
    BOOST_REQUIRE(plane.stored_name("mix-1") == "mix-1");

    err = "prior";
    BOOST_REQUIRE(!plane.Request("mix-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmMixedHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("mix-1"));
    BOOST_REQUIRE(plane.requested("mix-2"));
    BOOST_REQUIRE(plane.stored_name("mix-1") == "mix-1");
    BOOST_REQUIRE(plane.stored_name("mix-2") == "mix-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(space_and_code_word_are_stored_and_stay_stopped)
{
    modelnet::SwarmMixedHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request(" ", err));
    BOOST_REQUIRE(err == modelnet::kSwarmMixedHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested(" "));
    BOOST_REQUIRE(plane.stored_name(" ") == " ");
    BOOST_REQUIRE(!plane.running());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("PRECISION", err));
    BOOST_REQUIRE(err == modelnet::kSwarmMixedHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("PRECISION"));
    BOOST_REQUIRE(plane.stored_name("PRECISION") == "PRECISION");
    BOOST_REQUIRE(plane.requested(" "));
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
