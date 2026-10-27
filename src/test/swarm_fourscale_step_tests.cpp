// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/swarm_fourscale.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fourscale_step_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_step_on_daily_leaves_the_others_at_zero)
{
    modelnet::SwarmFourScale plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());

    BOOST_REQUIRE(plane.Step("daily", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);
    BOOST_REQUIRE(plane.scale_count() == 4);
    BOOST_REQUIRE(plane.holds("online"));
    BOOST_REQUIRE(plane.holds("daily"));
    BOOST_REQUIRE(plane.holds("weekly"));
    BOOST_REQUIRE(plane.holds("generational"));
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(each_known_scale_increments_alone)
{
    modelnet::SwarmFourScale plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());

    BOOST_REQUIRE(plane.Step("online", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);

    BOOST_REQUIRE(plane.Step("weekly", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);

    BOOST_REQUIRE(plane.Step("generational", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 1);

    BOOST_REQUIRE(plane.Step("online", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 2);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 1);
    BOOST_REQUIRE(plane.scale_count() == 4);
}

BOOST_AUTO_TEST_CASE(step_before_open_is_scale_and_stores_nothing)
{
    modelnet::SwarmFourScale plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Step("online", err));
    BOOST_REQUIRE_EQUAL(err, "SCALE");
    BOOST_REQUIRE(!plane.opened());
    BOOST_REQUIRE(plane.scale_count() == 0);
    BOOST_REQUIRE(!plane.holds("online"));
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Step("daily", err));
    BOOST_REQUIRE_EQUAL(err, "SCALE");
    BOOST_REQUIRE(plane.scale_count() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Step("", err));
    BOOST_REQUIRE_EQUAL(err, "SCALE");
    BOOST_REQUIRE(!plane.opened());
    BOOST_REQUIRE(plane.scale_count() == 0);
    BOOST_REQUIRE(!plane.holds(""));

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);
    BOOST_REQUIRE(plane.scale_count() == 4);
}

BOOST_AUTO_TEST_CASE(unknown_scale_is_scale_and_stores_nothing)
{
    modelnet::SwarmFourScale plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Step("daily", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Step("", err));
    BOOST_REQUIRE_EQUAL(err, "SCALE");
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);
    BOOST_REQUIRE(!plane.holds(""));
    BOOST_REQUIRE(plane.scale_count() == 4);

    err = "prior";
    BOOST_REQUIRE(!plane.Step("hourly", err));
    BOOST_REQUIRE_EQUAL(err, "SCALE");

    err = "prior";
    BOOST_REQUIRE(!plane.Step("Online", err));
    BOOST_REQUIRE_EQUAL(err, "SCALE");

    err = "prior";
    BOOST_REQUIRE(!plane.Step("immediate", err));
    BOOST_REQUIRE_EQUAL(err, "SCALE");

    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);
    BOOST_REQUIRE(plane.scale_count() == 4);
    BOOST_REQUIRE(!plane.holds("hourly"));
    BOOST_REQUIRE(!plane.holds("Online"));
    BOOST_REQUIRE(!plane.holds("immediate"));
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
