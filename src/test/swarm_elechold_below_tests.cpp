// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/swarm_elechold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_elechold_below_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(watt_hours_below_one_are_measure_and_store_nothing)
{
    modelnet::SwarmElecHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Measure(int64_t{0}, err));
    BOOST_REQUIRE_EQUAL(err, "MEASURE");
    BOOST_REQUIRE(!plane.measured());
    BOOST_REQUIRE(plane.watt_hours() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Measure(int64_t{-1}, err));
    BOOST_REQUIRE_EQUAL(err, "MEASURE");
    BOOST_REQUIRE(plane.watt_hours() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Measure(INT64_MIN, err));
    BOOST_REQUIRE_EQUAL(err, "MEASURE");
    BOOST_REQUIRE(!plane.measured());
    BOOST_REQUIRE(plane.watt_hours() == 0);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(below_one_after_a_measurement_keeps_the_stored_watt_hours)
{
    modelnet::SwarmElecHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Measure(int64_t{7}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.watt_hours() == 7);

    err = "prior";
    BOOST_REQUIRE(!plane.Measure(int64_t{0}, err));
    BOOST_REQUIRE_EQUAL(err, "MEASURE");
    BOOST_REQUIRE(plane.measured());
    BOOST_REQUIRE(plane.watt_hours() == 7);

    err = "prior";
    BOOST_REQUIRE(!plane.Measure(int64_t{-5}, err));
    BOOST_REQUIRE_EQUAL(err, "MEASURE");
    BOOST_REQUIRE(plane.watt_hours() == 7);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(below_one_does_not_block_a_later_measurement)
{
    modelnet::SwarmElecHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Measure(int64_t{0}, err));
    BOOST_REQUIRE_EQUAL(err, "MEASURE");
    BOOST_REQUIRE(plane.watt_hours() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Measure(int64_t{0}, err));
    BOOST_REQUIRE_EQUAL(err, "MEASURE");
    BOOST_REQUIRE(plane.watt_hours() == 0);

    err = "prior";
    BOOST_REQUIRE(plane.Measure(int64_t{7}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.measured());
    BOOST_REQUIRE(plane.watt_hours() == 7);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
