// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ablatehold/codes.h>
#include <modelnet/swarm_ablatehold/limits.h>
#include <modelnet/swarm_ablatehold/swarm_ablatehold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_ablatehold_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_request_of_the_same_name_is_replay)
{
    modelnet::SwarmAblateHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("ablate-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmAblateHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("ablate-1"));
    BOOST_REQUIRE(plane.stored_name("ablate-1") == "ablate-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.published());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ablate-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmAblateHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.requested("ablate-1"));
    BOOST_REQUIRE(plane.stored_name("ablate-1") == "ablate-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(plane.published() == modelnet::kSwarmAblateHoldPublished);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ablate-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmAblateHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_name("ablate-1") == "ablate-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_name_is_ablation_before_replay)
{
    modelnet::SwarmAblateHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("ablate-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmAblateHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("ablate-1"));
    BOOST_REQUIRE(!plane.published());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmAblateHoldAblation);
    BOOST_REQUIRE_EQUAL(err, "ABLATION");
    BOOST_REQUIRE(plane.stored_name("ablate-1") == "ablate-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_when_another_name_is_stored)
{
    modelnet::SwarmAblateHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("ablate-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmAblateHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.published());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ablate-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmAblateHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.published());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ablate-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmAblateHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.requested("ablate-1"));
    BOOST_REQUIRE(plane.requested("ablate-2"));
    BOOST_REQUIRE(plane.stored_name("ablate-1") == "ablate-1");
    BOOST_REQUIRE(plane.stored_name("ablate-2") == "ablate-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmAblateHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
