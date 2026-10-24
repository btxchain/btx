// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradhold/limits.h>
#include <modelnet/swarm_gradhold/swarm_gradhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void RequireStill(const modelnet::SwarmGradHold& plane)
{
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmGradHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmGradHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmGradHoldLaunched);
    BOOST_REQUIRE(!plane.exported());
    BOOST_REQUIRE(plane.exported() == modelnet::kSwarmGradHoldExported);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_gradhold_bytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bytes_gpu_and_launch_stay_fixed)
{
    modelnet::SwarmGradHold plane;
    std::string err = "prior";

    RequireStill(plane);

    BOOST_REQUIRE(!plane.Offer("", err));
    BOOST_REQUIRE_EQUAL(err, "UPDATE");
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(plane.Offer("grad-1", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.offered("grad-1"));
    BOOST_REQUIRE(plane.stored_id("grad-1") == "grad-1");
    BOOST_REQUIRE(plane.offer_count() == 1);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Offer("grad-1", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_id("grad-1") == "grad-1");
    BOOST_REQUIRE(plane.offer_count() == 1);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Export("grad-1", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_EXPORTED");
    BOOST_REQUIRE(plane.stored_id("grad-1") == "grad-1");
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Export("missing", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_EXPORTED");
    BOOST_REQUIRE(!plane.offered("missing"));
    BOOST_REQUIRE(plane.offer_count() == 1);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Export("", err));
    BOOST_REQUIRE_EQUAL(err, "UPDATE");
    BOOST_REQUIRE(plane.stored_id("grad-1") == "grad-1");
    BOOST_REQUIRE(plane.offer_count() == 1);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(plane.Offer("grad-2", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.stored_id("grad-2") == "grad-2");
    BOOST_REQUIRE(plane.offer_count() == 2);
    RequireStill(plane);
}

BOOST_AUTO_TEST_SUITE_END()
