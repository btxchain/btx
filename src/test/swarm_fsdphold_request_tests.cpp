// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fsdphold/codes.h>
#include <modelnet/swarm_fsdphold/limits.h>
#include <modelnet/swarm_fsdphold/swarm_fsdphold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fsdphold_request_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_request_stays_stopped)
{
    modelnet::SwarmFsdpHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.requested("fsdp-1"));
    BOOST_REQUIRE(plane.stored_name("fsdp-1").empty());
    BOOST_REQUIRE(plane.request_count() == 0);
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(!plane.Request("fsdp-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmFsdpHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("fsdp-1"));
    BOOST_REQUIRE(plane.stored_name("fsdp-1") == "fsdp-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE(plane.running() == modelnet::kSwarmFsdpHoldRunning);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmFsdpHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmFsdpHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmFsdpHoldLaunched);
}

BOOST_AUTO_TEST_CASE(a_second_distinct_name_is_stored_beside_the_first)
{
    modelnet::SwarmFsdpHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("fsdp-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmFsdpHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("fsdp-1"));
    BOOST_REQUIRE(plane.stored_name("fsdp-1") == "fsdp-1");
    BOOST_REQUIRE(!plane.running());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("fsdp-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmFsdpHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("fsdp-1"));
    BOOST_REQUIRE(plane.requested("fsdp-2"));
    BOOST_REQUIRE(plane.stored_name("fsdp-1") == "fsdp-1");
    BOOST_REQUIRE(plane.stored_name("fsdp-2") == "fsdp-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(space_and_code_word_are_stored_and_stay_stopped)
{
    modelnet::SwarmFsdpHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request(" ", err));
    BOOST_REQUIRE(err == modelnet::kSwarmFsdpHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested(" "));
    BOOST_REQUIRE(plane.stored_name(" ") == " ");
    BOOST_REQUIRE(!plane.running());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("FSDP", err));
    BOOST_REQUIRE(err == modelnet::kSwarmFsdpHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("FSDP"));
    BOOST_REQUIRE(plane.stored_name("FSDP") == "FSDP");
    BOOST_REQUIRE(plane.requested(" "));
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
