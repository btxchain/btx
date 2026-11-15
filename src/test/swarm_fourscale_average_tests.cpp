// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/swarm_fourscale.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fourscale_average_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(average_before_open_is_not_averaged)
{
    modelnet::SwarmFourScale plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Average(err));
    BOOST_REQUIRE_EQUAL(err, "NOT_AVERAGED");
    BOOST_REQUIRE(!plane.opened());
    BOOST_REQUIRE(plane.scale_count() == 0);
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(average_after_steps_leaves_each_step)
{
    modelnet::SwarmFourScale plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Step("online", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Step("daily", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Step("daily", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Average(err));
    BOOST_REQUIRE_EQUAL(err, "NOT_AVERAGED");
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 2);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);
    BOOST_REQUIRE(plane.scale_count() == 4);
    BOOST_REQUIRE(!plane.graduated());

    err = "prior";
    BOOST_REQUIRE(!plane.Average(err));
    BOOST_REQUIRE_EQUAL(err, "NOT_AVERAGED");
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 2);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
