// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradhold/limits.h>
#include <modelnet/swarm_gradhold/swarm_gradhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_gradhold_export_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(export_of_a_stored_update_is_not_exported)
{
    modelnet::SwarmGradHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Offer("grad-1", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.offered("grad-1"));
    BOOST_REQUIRE(plane.offer_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Export("grad-1", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_EXPORTED");
    BOOST_REQUIRE(plane.offered("grad-1"));
    BOOST_REQUIRE(plane.stored_id("grad-1") == "grad-1");
    BOOST_REQUIRE(plane.offer_count() == 1);
    BOOST_REQUIRE(!plane.exported());
    BOOST_REQUIRE(plane.exported() == modelnet::kSwarmGradHoldExported);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Export("grad-1", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_EXPORTED");
    BOOST_REQUIRE(plane.stored_id("grad-1") == "grad-1");
    BOOST_REQUIRE(plane.offer_count() == 1);
    BOOST_REQUIRE(!plane.exported());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(export_of_an_unknown_id_stores_nothing)
{
    modelnet::SwarmGradHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.offered("missing"));
    BOOST_REQUIRE(plane.offer_count() == 0);

    BOOST_REQUIRE(!plane.Export("missing", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_EXPORTED");
    BOOST_REQUIRE(!plane.offered("missing"));
    BOOST_REQUIRE(plane.stored_id("missing").empty());
    BOOST_REQUIRE(plane.offer_count() == 0);
    BOOST_REQUIRE(!plane.exported());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(plane.Offer("grad-1", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Export("missing", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_EXPORTED");
    BOOST_REQUIRE(!plane.offered("missing"));
    BOOST_REQUIRE(plane.offered("grad-1"));
    BOOST_REQUIRE(plane.stored_id("grad-1") == "grad-1");
    BOOST_REQUIRE(plane.offer_count() == 1);
    BOOST_REQUIRE(!plane.exported());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
