// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rescap/codes.h>
#include <modelnet/swarm_rescap/limits.h>
#include <modelnet/swarm_rescap/swarm_rescap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_rescap_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_raise_of_the_same_count_is_replay)
{
    modelnet::SwarmResCap plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Raise(12, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE(plane.stored(12));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(12), 12);
    BOOST_REQUIRE(plane.raise_count() == 1);
    BOOST_REQUIRE(!plane.raised());

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(12, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored(12));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(12), 12);
    BOOST_REQUIRE(plane.raise_count() == 1);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE(plane.raised() == modelnet::kSwarmResCapRaised);
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
    BOOST_REQUIRE(plane.cap_threads() == modelnet::kSwarmResCapThreadCap);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(12, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.stored_threads(12), 12);
    BOOST_REQUIRE(plane.raise_count() == 1);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_when_another_count_is_stored)
{
    modelnet::SwarmResCap plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Raise(1, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(64, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(1, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored(1));
    BOOST_REQUIRE(plane.stored(64));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(1), 1);
    BOOST_REQUIRE_EQUAL(plane.stored_threads(64), 64);
    BOOST_REQUIRE(plane.raise_count() == 2);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmResCapBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(below_one_is_cap_before_replay)
{
    modelnet::SwarmResCap plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Raise(7, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(0, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCap);
    BOOST_REQUIRE_EQUAL(err, "CAP");
    BOOST_REQUIRE_EQUAL(plane.stored_threads(7), 7);
    BOOST_REQUIRE(plane.raise_count() == 1);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(above_64_is_capped_before_replay)
{
    modelnet::SwarmResCap plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Raise(7, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(65, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE(err != modelnet::kSwarmResCapReplay);
    BOOST_REQUIRE(!plane.stored(65));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(7), 7);
    BOOST_REQUIRE(plane.raise_count() == 1);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
