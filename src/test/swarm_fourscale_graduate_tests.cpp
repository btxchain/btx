// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/swarm_fourscale.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fourscale_graduate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(graduate_before_open_is_realm)
{
    modelnet::SwarmFourScale plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.Graduate(err));
    BOOST_REQUIRE_EQUAL(err, "REALM");
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.opened());
    BOOST_REQUIRE(plane.scale_count() == 0);
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(graduate_after_steps_leaves_steps_and_stays_ungraduated)
{
    modelnet::SwarmFourScale plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Step("weekly", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Step("generational", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Step("generational", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Average(err));
    BOOST_REQUIRE_EQUAL(err, "NOT_AVERAGED");

    err = "prior";
    BOOST_REQUIRE(!plane.Graduate(err));
    BOOST_REQUIRE_EQUAL(err, "REALM");
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE(plane.scale_count() == 4);
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 2);

    err = "prior";
    BOOST_REQUIRE(!plane.Graduate(err));
    BOOST_REQUIRE_EQUAL(err, "REALM");
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 2);
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
