// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradhold/limits.h>
#include <modelnet/swarm_gradhold/swarm_gradhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_gradhold_offer_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(non_empty_update_id_is_stored)
{
    modelnet::SwarmGradHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.offered("grad-1"));
    BOOST_REQUIRE(plane.stored_id("grad-1").empty());
    BOOST_REQUIRE(plane.offer_count() == 0);
    BOOST_REQUIRE(!plane.exported());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(plane.Offer("grad-1", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.offered("grad-1"));
    BOOST_REQUIRE(plane.stored_id("grad-1") == "grad-1");
    BOOST_REQUIRE(plane.offer_count() == 1);
    BOOST_REQUIRE(!plane.exported());
    BOOST_REQUIRE(plane.exported() == modelnet::kSwarmGradHoldExported);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmGradHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmGradHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmGradHoldLaunched);
}

BOOST_AUTO_TEST_CASE(a_second_distinct_id_is_stored_beside_the_first)
{
    modelnet::SwarmGradHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Offer("grad-1", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.stored_id("grad-1") == "grad-1");

    err = "prior";
    BOOST_REQUIRE(plane.Offer("grad-2", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.offered("grad-1"));
    BOOST_REQUIRE(plane.offered("grad-2"));
    BOOST_REQUIRE(plane.stored_id("grad-1") == "grad-1");
    BOOST_REQUIRE(plane.stored_id("grad-2") == "grad-2");
    BOOST_REQUIRE(plane.offer_count() == 2);
    BOOST_REQUIRE(!plane.exported());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
