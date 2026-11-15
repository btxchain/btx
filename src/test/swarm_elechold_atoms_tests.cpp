// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/limits.h>
#include <modelnet/swarm_elechold/swarm_elechold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void RequireNoAtoms(const modelnet::SwarmElecHold& plane)
{
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.charged() == modelnet::kSwarmElecHoldCharged);
    BOOST_REQUIRE(plane.atoms_moved() == 0);
    BOOST_REQUIRE(plane.atoms_moved() == modelnet::kSwarmElecHoldAtomsMoved);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_elechold_atoms_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(atoms_stay_zero_across_measure_replay_and_charge)
{
    modelnet::SwarmElecHold plane;
    std::string err = "prior";

    RequireNoAtoms(plane);
    BOOST_REQUIRE(plane.watt_hours() == 0);

    BOOST_REQUIRE(!plane.Measure(int64_t{0}, err));
    BOOST_REQUIRE_EQUAL(err, "MEASURE");
    RequireNoAtoms(plane);
    BOOST_REQUIRE(plane.watt_hours() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Charge(int64_t{0}, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    RequireNoAtoms(plane);
    BOOST_REQUIRE(plane.watt_hours() == 0);

    err = "prior";
    BOOST_REQUIRE(plane.Measure(int64_t{3}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.watt_hours() == 3);
    RequireNoAtoms(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Measure(int64_t{8}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.watt_hours() == 3);
    RequireNoAtoms(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Charge(int64_t{100}, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.watt_hours() == 3);
    RequireNoAtoms(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Charge(int64_t{-1}, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.watt_hours() == 3);
    RequireNoAtoms(plane);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE(!plane.charged());
}

BOOST_AUTO_TEST_SUITE_END()
