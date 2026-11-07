// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/limits.h>
#include <modelnet/swarm_fourscale/swarm_fourscale.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <string>

namespace {

void RequirePlantedAtZero(const modelnet::SwarmFourScale& plane)
{
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE(plane.scale_count() == 4);
    BOOST_REQUIRE(plane.scale_count() == static_cast<std::size_t>(modelnet::kSwarmFourScaleCount));
    BOOST_REQUIRE(plane.holds("online"));
    BOOST_REQUIRE(plane.holds("daily"));
    BOOST_REQUIRE(plane.holds("weekly"));
    BOOST_REQUIRE(plane.holds("generational"));
    BOOST_REQUIRE(!plane.holds(""));
    BOOST_REQUIRE(!plane.holds("hourly"));
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);
    BOOST_REQUIRE(plane.steps("online") == modelnet::kSwarmFourScaleInitialStep);
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_fourscale_open_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(open_plants_four_scales_at_step_zero)
{
    modelnet::SwarmFourScale plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.opened());
    BOOST_REQUIRE(plane.scale_count() == 0);
    BOOST_REQUIRE(!plane.holds("online"));
    BOOST_REQUIRE(!plane.holds("daily"));
    BOOST_REQUIRE(!plane.holds("weekly"));
    BOOST_REQUIRE(!plane.holds("generational"));
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());
    RequirePlantedAtZero(plane);
}

BOOST_AUTO_TEST_SUITE_END()
