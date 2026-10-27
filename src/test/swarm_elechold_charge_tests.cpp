// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/limits.h>
#include <modelnet/swarm_elechold/swarm_elechold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_elechold_charge_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(charge_before_a_measurement_is_held_and_stores_nothing)
{
    modelnet::SwarmElecHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.watt_hours() == 0);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);

    BOOST_REQUIRE(!plane.Charge(int64_t{8}, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.measured());
    BOOST_REQUIRE(plane.watt_hours() == 0);
    BOOST_REQUIRE(plane.watt_hours() == modelnet::kSwarmElecHoldUnset);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.charged() == modelnet::kSwarmElecHoldCharged);
    BOOST_REQUIRE(plane.atoms_moved() == 0);
    BOOST_REQUIRE(plane.atoms_moved() == modelnet::kSwarmElecHoldAtomsMoved);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");

    err = "prior";
    BOOST_REQUIRE(!plane.Charge(int64_t{0}, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.watt_hours() == 0);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Charge(int64_t{-3}, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.watt_hours() == 0);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
}

BOOST_AUTO_TEST_CASE(charge_after_a_measurement_is_held_and_keeps_the_watt_hours)
{
    modelnet::SwarmElecHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Measure(int64_t{15}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.watt_hours() == 15);

    err = "prior";
    BOOST_REQUIRE(!plane.Charge(int64_t{15}, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.measured());
    BOOST_REQUIRE(plane.watt_hours() == 15);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");

    err = "prior";
    BOOST_REQUIRE(!plane.Charge(int64_t{0}, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.watt_hours() == 15);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Charge(INT64_MAX, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.watt_hours() == 15);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Measure(int64_t{15}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.watt_hours() == 15);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
}

BOOST_AUTO_TEST_CASE(charge_after_a_refused_measurement_stores_nothing)
{
    modelnet::SwarmElecHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Measure(int64_t{0}, err));
    BOOST_REQUIRE_EQUAL(err, "MEASURE");

    err = "prior";
    BOOST_REQUIRE(!plane.Charge(int64_t{6}, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.measured());
    BOOST_REQUIRE(plane.watt_hours() == 0);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.gpu());

    err = "prior";
    BOOST_REQUIRE(plane.Measure(int64_t{6}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.watt_hours() == 6);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
