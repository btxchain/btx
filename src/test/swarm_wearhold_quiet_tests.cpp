// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearhold/limits.h>
#include <modelnet/swarm_wearhold/swarm_wearhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void RequireQuiet(const modelnet::SwarmWearHold& plane)
{
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(plane.automatic_spend() == modelnet::kSwarmWearHoldAutomaticSpend);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.broadcast() == modelnet::kSwarmWearHoldBroadcast);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmWearHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmWearHoldGpu);
    BOOST_REQUIRE(!plane.charged());
    BOOST_REQUIRE(plane.atoms_moved() == 0);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_wearhold_quiet_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(quiet_flags_stay_fixed_across_measure_replay_and_charge)
{
    modelnet::SwarmWearHold plane;
    std::string err = "prior";

    RequireQuiet(plane);
    BOOST_REQUIRE(plane.joules() == 0);

    BOOST_REQUIRE(!plane.Measure(int64_t{0}, err));
    BOOST_REQUIRE_EQUAL(err, "MEASURE");
    RequireQuiet(plane);
    BOOST_REQUIRE(plane.joules() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Charge(int64_t{2}, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    RequireQuiet(plane);
    BOOST_REQUIRE(plane.joules() == 0);

    err = "prior";
    BOOST_REQUIRE(plane.Measure(int64_t{22}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.joules() == 22);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Measure(int64_t{22}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.joules() == 22);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Charge(int64_t{22}, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.joules() == 22);
    RequireQuiet(plane);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
