// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/limits.h>
#include <modelnet/swarm_elechold/swarm_elechold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_elechold_measure_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_watt_hour_is_stored)
{
    modelnet::SwarmElecHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.measured());
    BOOST_REQUIRE(plane.watt_hours() == 0);
    BOOST_REQUIRE(plane.watt_hours() == modelnet::kSwarmElecHoldUnset);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);

    BOOST_REQUIRE(plane.Measure(int64_t{1}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.measured());
    BOOST_REQUIRE(plane.watt_hours() == 1);
    BOOST_REQUIRE(plane.watt_hours() == modelnet::kSwarmElecHoldMinWattHour);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.charged() == modelnet::kSwarmElecHoldCharged);
    BOOST_REQUIRE(plane.atoms_moved() == 0);
    BOOST_REQUIRE(plane.atoms_moved() == modelnet::kSwarmElecHoldAtomsMoved);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(a_larger_watt_hour_count_is_stored_as_given)
{
    modelnet::SwarmElecHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Measure(int64_t{40}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.measured());
    BOOST_REQUIRE(plane.watt_hours() == 40);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
