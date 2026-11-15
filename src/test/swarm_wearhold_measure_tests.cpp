// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearhold/limits.h>
#include <modelnet/swarm_wearhold/swarm_wearhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_wearhold_measure_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_joule_is_stored)
{
    modelnet::SwarmWearHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.measured());
    BOOST_REQUIRE(plane.joules() == 0);
    BOOST_REQUIRE(plane.joules() == modelnet::kSwarmWearHoldUnset);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);

    BOOST_REQUIRE(plane.Measure(int64_t{1}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.measured());
    BOOST_REQUIRE(plane.joules() == 1);
    BOOST_REQUIRE(plane.joules() == modelnet::kSwarmWearHoldMinJoule);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.charged() == modelnet::kSwarmWearHoldCharged);
    BOOST_REQUIRE(plane.atoms_moved() == 0);
    BOOST_REQUIRE(plane.atoms_moved() == modelnet::kSwarmWearHoldAtomsMoved);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(a_larger_joule_count_is_stored_as_given)
{
    modelnet::SwarmWearHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Measure(int64_t{40}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.measured());
    BOOST_REQUIRE(plane.joules() == 40);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
