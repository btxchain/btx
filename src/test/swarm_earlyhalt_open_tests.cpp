// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/earlyhalt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_earlyhalt_open_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(budget_below_one_stores_nothing)
{
    modelnet::SwarmEarlyHalt plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Open(0, err));
    BOOST_REQUIRE_EQUAL(err, "BUDGET");
    BOOST_REQUIRE(!plane.opened());
    BOOST_REQUIRE_EQUAL(plane.budget(), 0);
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE(!plane.has_score());
    BOOST_REQUIRE(!plane.early_stop());

    err = "prior";
    BOOST_REQUIRE(!plane.Open(-4, err));
    BOOST_REQUIRE_EQUAL(err, "BUDGET");
    BOOST_REQUIRE(!plane.opened());
    BOOST_REQUIRE_EQUAL(plane.budget(), 0);
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE(!plane.has_score());
    BOOST_REQUIRE(!plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(second_open_leaves_the_first_budget)
{
    modelnet::SwarmEarlyHalt plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(3, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE_EQUAL(plane.budget(), 3);
    BOOST_REQUIRE_EQUAL(plane.remaining(), 3);
    BOOST_REQUIRE(!plane.has_score());
    BOOST_REQUIRE(!plane.early_stop());

    err = "prior";
    BOOST_REQUIRE(!plane.Open(9, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE_EQUAL(plane.budget(), 3);
    BOOST_REQUIRE_EQUAL(plane.remaining(), 3);
    BOOST_REQUIRE(!plane.has_score());
    BOOST_REQUIRE(!plane.early_stop());

    err = "prior";
    BOOST_REQUIRE(!plane.Open(0, err));
    BOOST_REQUIRE_EQUAL(err, "BUDGET");
    BOOST_REQUIRE_EQUAL(plane.budget(), 3);
    BOOST_REQUIRE_EQUAL(plane.remaining(), 3);
}

BOOST_AUTO_TEST_CASE(step_before_open_stores_nothing)
{
    modelnet::SwarmEarlyHalt plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Step(10, err));
    BOOST_REQUIRE_EQUAL(err, "STEP");
    BOOST_REQUIRE(!plane.opened());
    BOOST_REQUIRE_EQUAL(plane.budget(), 0);
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE(!plane.has_score());
    BOOST_REQUIRE_EQUAL(plane.score(), 0);
    BOOST_REQUIRE(!plane.early_stop());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
