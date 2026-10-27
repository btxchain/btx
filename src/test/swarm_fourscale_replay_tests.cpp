// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/swarm_fourscale.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fourscale_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_open_is_replay_and_leaves_steps)
{
    modelnet::SwarmFourScale plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());

    BOOST_REQUIRE(plane.Step("daily", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Step("daily", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Step("weekly", err));
    BOOST_REQUIRE(err.empty());

    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 2);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Open(err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.opened());
    BOOST_REQUIRE(plane.scale_count() == 4);
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 2);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);
    BOOST_REQUIRE(!plane.graduated());

    err = "prior";
    BOOST_REQUIRE(!plane.Open(err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 2);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 1);
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(second_open_before_any_step_keeps_zeros)
{
    modelnet::SwarmFourScale plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Open(err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.scale_count() == 4);
    BOOST_REQUIRE_EQUAL(plane.steps("online"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("daily"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("weekly"), 0);
    BOOST_REQUIRE_EQUAL(plane.steps("generational"), 0);
}

BOOST_AUTO_TEST_SUITE_END()
