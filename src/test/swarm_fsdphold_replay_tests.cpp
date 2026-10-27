// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fsdphold/codes.h>
#include <modelnet/swarm_fsdphold/limits.h>
#include <modelnet/swarm_fsdphold/swarm_fsdphold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fsdphold_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_request_of_the_same_name_is_replay)
{
    modelnet::SwarmFsdpHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("fsdp-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmFsdpHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("fsdp-1"));
    BOOST_REQUIRE(plane.stored_name("fsdp-1") == "fsdp-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.running());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("fsdp-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmFsdpHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.requested("fsdp-1"));
    BOOST_REQUIRE(plane.stored_name("fsdp-1") == "fsdp-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE(plane.running() == modelnet::kSwarmFsdpHoldRunning);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("fsdp-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmFsdpHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_name("fsdp-1") == "fsdp-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_name_is_fsdp_before_replay)
{
    modelnet::SwarmFsdpHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("fsdp-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmFsdpHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmFsdpHoldFsdp);
    BOOST_REQUIRE_EQUAL(err, "FSDP");
    BOOST_REQUIRE(plane.stored_name("fsdp-1") == "fsdp-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_when_another_name_is_stored)
{
    modelnet::SwarmFsdpHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("fsdp-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmFsdpHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");

    err = "prior";
    BOOST_REQUIRE(!plane.Request("fsdp-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmFsdpHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");

    err = "prior";
    BOOST_REQUIRE(!plane.Request("fsdp-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmFsdpHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.requested("fsdp-1"));
    BOOST_REQUIRE(plane.requested("fsdp-2"));
    BOOST_REQUIRE(plane.stored_name("fsdp-1") == "fsdp-1");
    BOOST_REQUIRE(plane.stored_name("fsdp-2") == "fsdp-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmFsdpHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
