// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/earlyhalt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_earlyhalt_step_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(falling_score_stops_and_keeps_the_row)
{
    modelnet::SwarmEarlyHalt plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(5, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.remaining(), 5);

    BOOST_REQUIRE(plane.Step(10, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.remaining(), 4);
    BOOST_REQUIRE(plane.has_score());
    BOOST_REQUIRE_EQUAL(plane.score(), 10);
    BOOST_REQUIRE(!plane.early_stop());

    BOOST_REQUIRE(plane.Step(12, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.remaining(), 3);
    BOOST_REQUIRE_EQUAL(plane.score(), 12);
    BOOST_REQUIRE(!plane.early_stop());

    BOOST_REQUIRE(plane.Step(11, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE_EQUAL(plane.score(), 11);
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE_EQUAL(plane.budget(), 5);
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(later_step_is_refused_and_stores_nothing)
{
    modelnet::SwarmEarlyHalt plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(4, err));
    BOOST_REQUIRE(plane.Step(20, err));
    BOOST_REQUIRE(plane.Step(19, err));
    BOOST_REQUIRE(plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE_EQUAL(plane.score(), 19);
    BOOST_REQUIRE_EQUAL(plane.budget(), 4);

    err = "prior";
    BOOST_REQUIRE(!plane.Step(100, err));
    BOOST_REQUIRE_EQUAL(err, "STOPPED");
    BOOST_REQUIRE(plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE_EQUAL(plane.score(), 19);
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE_EQUAL(plane.budget(), 4);

    err = "prior";
    BOOST_REQUIRE(!plane.Step(-1, err));
    BOOST_REQUIRE_EQUAL(err, "STOPPED");
    BOOST_REQUIRE_EQUAL(plane.score(), 19);
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE(plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(negative_drop_stops_after_the_first_score)
{
    modelnet::SwarmEarlyHalt plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(2, err));
    BOOST_REQUIRE(plane.Step(-5, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.score(), -5);
    BOOST_REQUIRE_EQUAL(plane.remaining(), 1);
    BOOST_REQUIRE(!plane.early_stop());

    BOOST_REQUIRE(plane.Step(-6, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE_EQUAL(plane.score(), -6);
    BOOST_REQUIRE_EQUAL(plane.budget(), 2);
}

BOOST_AUTO_TEST_CASE(spent_budget_refuses_a_later_step)
{
    modelnet::SwarmEarlyHalt plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(1, err));
    BOOST_REQUIRE(plane.Step(7, err));
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE(!plane.early_stop());
    BOOST_REQUIRE_EQUAL(plane.score(), 7);

    err = "prior";
    BOOST_REQUIRE(!plane.Step(8, err));
    BOOST_REQUIRE_EQUAL(err, "STOPPED");
    BOOST_REQUIRE_EQUAL(plane.score(), 7);
    BOOST_REQUIRE_EQUAL(plane.remaining(), 0);
    BOOST_REQUIRE(!plane.early_stop());
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE_EQUAL(plane.budget(), 1);
}

BOOST_AUTO_TEST_SUITE_END()
