// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/limits.h>
#include <modelnet/swarm_fourscale/swarm_fourscale.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void RequireQuiet(const modelnet::SwarmFourScale& plane)
{
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmFourScaleBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmFourScaleGpu);
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(plane.graduated() == modelnet::kSwarmFourScaleGraduated);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_fourscale_bytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bytes_stay_zero_and_gpu_stays_false)
{
    modelnet::SwarmFourScale plane;
    std::string err = "prior";

    RequireQuiet(plane);

    BOOST_REQUIRE(!plane.Step("daily", err));
    BOOST_REQUIRE_EQUAL(err, "SCALE");
    RequireQuiet(plane);

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());
    RequireQuiet(plane);

    BOOST_REQUIRE(plane.Step("online", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Step("", err));
    BOOST_REQUIRE_EQUAL(err, "SCALE");
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Step("hourly", err));
    BOOST_REQUIRE_EQUAL(err, "SCALE");
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 1);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Open(err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 1);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Average(err));
    BOOST_REQUIRE_EQUAL(err, "NOT_AVERAGED");
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Graduate(err));
    BOOST_REQUIRE_EQUAL(err, "REALM");
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
