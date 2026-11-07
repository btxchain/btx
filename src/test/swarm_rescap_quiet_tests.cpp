// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rescap/codes.h>
#include <modelnet/swarm_rescap/limits.h>
#include <modelnet/swarm_rescap/swarm_rescap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void RequireStill(const modelnet::SwarmResCap& plane)
{
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmResCapBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmResCapGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmResCapLaunched);
    BOOST_REQUIRE(!plane.raised());
    BOOST_REQUIRE(plane.raised() == modelnet::kSwarmResCapRaised);
    BOOST_REQUIRE_EQUAL(plane.cap_threads(), 64);
    BOOST_REQUIRE(plane.cap_threads() == modelnet::kSwarmResCapThreadCap);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_rescap_quiet_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(quiet_flags_stay_fixed_across_raise_replay_and_refusal)
{
    modelnet::SwarmResCap plane;
    std::string err = "prior";

    RequireStill(plane);

    BOOST_REQUIRE(!plane.Raise(0, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCap);
    BOOST_REQUIRE_EQUAL(err, "CAP");
    BOOST_REQUIRE(plane.raise_count() == 0);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(65, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE(plane.raise_count() == 0);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(16, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE(plane.stored(16));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(16), 16);
    BOOST_REQUIRE(plane.raise_count() == 1);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(16, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.stored_threads(16), 16);
    BOOST_REQUIRE(plane.raise_count() == 1);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(64, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE_EQUAL(plane.stored_threads(64), 64);
    BOOST_REQUIRE(plane.raise_count() == 2);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(0, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCap);
    BOOST_REQUIRE_EQUAL(err, "CAP");
    BOOST_REQUIRE_EQUAL(plane.stored_threads(16), 16);
    BOOST_REQUIRE_EQUAL(plane.stored_threads(64), 64);
    BOOST_REQUIRE(plane.raise_count() == 2);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Raise(99, err));
    BOOST_REQUIRE(err == modelnet::kSwarmResCapCapped);
    BOOST_REQUIRE_EQUAL(err, "CAPPED");
    BOOST_REQUIRE(!plane.stored(99));
    BOOST_REQUIRE_EQUAL(plane.stored_threads(16), 16);
    BOOST_REQUIRE(plane.raise_count() == 2);
    RequireStill(plane);
}

BOOST_AUTO_TEST_SUITE_END()
