// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearhold/replay.h>
#include <modelnet/swarm_wearhold/swarm_wearhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_wearhold_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_measure_is_replay_and_keeps_the_first_joules)
{
    modelnet::SwarmWearHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!modelnet::SwarmWearHoldIsReplay(modelnet::SwarmWearHoldBook{}, int64_t{12}));

    BOOST_REQUIRE(plane.Measure(int64_t{12}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.measured());
    BOOST_REQUIRE(plane.joules() == 12);

    err = "prior";
    BOOST_REQUIRE(!plane.Measure(int64_t{12}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.measured());
    BOOST_REQUIRE(plane.joules() == 12);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.gpu());

    err = "prior";
    BOOST_REQUIRE(!plane.Measure(int64_t{12}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.joules() == 12);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
}

BOOST_AUTO_TEST_CASE(a_different_second_count_is_replay)
{
    modelnet::SwarmWearHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Measure(int64_t{4}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.joules() == 4);

    err = "prior";
    BOOST_REQUIRE(!plane.Measure(int64_t{9}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.measured());
    BOOST_REQUIRE(plane.joules() == 4);

    err = "prior";
    BOOST_REQUIRE(!plane.Measure(INT64_MAX, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.joules() == 4);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(measure_below_one_is_decided_before_replay)
{
    modelnet::SwarmWearHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Measure(int64_t{4}, err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Measure(int64_t{0}, err));
    BOOST_REQUIRE_EQUAL(err, "MEASURE");
    BOOST_REQUIRE(plane.joules() == 4);

    err = "prior";
    BOOST_REQUIRE(!plane.Measure(int64_t{4}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.measured());
    BOOST_REQUIRE(plane.joules() == 4);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
