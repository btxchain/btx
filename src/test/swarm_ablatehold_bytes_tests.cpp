// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ablatehold/codes.h>
#include <modelnet/swarm_ablatehold/limits.h>
#include <modelnet/swarm_ablatehold/swarm_ablatehold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void RequireStill(const modelnet::SwarmAblateHold& plane)
{
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmAblateHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmAblateHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmAblateHoldLaunched);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(plane.published() == modelnet::kSwarmAblateHoldPublished);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_ablatehold_bytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bytes_stay_zero)
{
    modelnet::SwarmAblateHold plane;
    std::string err = "prior";

    RequireStill(plane);

    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmAblateHoldAblation);
    BOOST_REQUIRE_EQUAL(err, "ABLATION");
    BOOST_REQUIRE(plane.request_count() == 0);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ablate-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmAblateHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("ablate-1"));
    BOOST_REQUIRE(plane.stored_name("ablate-1") == "ablate-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.published());
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ablate-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmAblateHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_name("ablate-1") == "ablate-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.published());
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ablate-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmAblateHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored_name("ablate-2") == "ablate-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmAblateHoldAblation);
    BOOST_REQUIRE_EQUAL(err, "ABLATION");
    BOOST_REQUIRE(plane.stored_name("ablate-1") == "ablate-1");
    BOOST_REQUIRE(plane.stored_name("ablate-2") == "ablate-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    RequireStill(plane);
}

BOOST_AUTO_TEST_SUITE_END()
