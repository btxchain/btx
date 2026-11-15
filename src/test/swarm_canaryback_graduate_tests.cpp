// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryback/canaryback.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_canaryback_graduate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(graduate_is_realm_and_stays_ungraduated)
{
    modelnet::SwarmCanaryBack plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.Graduate(err));
    BOOST_REQUIRE_EQUAL(err, "REALM");
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.blocks(), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    const modelnet::SwarmCanaryBack& view = plane;
    err = "prior";
    BOOST_REQUIRE(!view.Graduate(err));
    BOOST_REQUIRE_EQUAL(err, "REALM");
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
}

BOOST_AUTO_TEST_CASE(graduate_leaves_active_after_adopt)
{
    modelnet::SwarmCanaryBack plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Stage("cand-a", err));
    BOOST_REQUIRE(plane.Adopt(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "cand-a");
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand-a");

    err = "prior";
    BOOST_REQUIRE(!plane.Graduate(err));
    BOOST_REQUIRE_EQUAL(err, "REALM");
    BOOST_REQUIRE_EQUAL(plane.active(), "cand-a");
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand-a");
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());

    BOOST_REQUIRE(plane.Regress(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.staged().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Graduate(err));
    BOOST_REQUIRE_EQUAL(err, "REALM");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.blocks(), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
