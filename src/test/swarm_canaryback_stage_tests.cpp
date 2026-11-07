// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryback/canaryback.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_canaryback_stage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(active_starts_at_base)
{
    const modelnet::SwarmCanaryBack plane;

    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.blocks(), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_id_is_id_and_stores_nothing)
{
    modelnet::SwarmCanaryBack plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Stage("", err));
    BOOST_REQUIRE_EQUAL(err, "ID");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    BOOST_REQUIRE(plane.Stage("cand-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand-a");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");

    err = "prior";
    BOOST_REQUIRE(!plane.Stage("", err));
    BOOST_REQUIRE_EQUAL(err, "ID");
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand-a");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(stage_stores_candidate_and_leaves_active)
{
    modelnet::SwarmCanaryBack plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Stage("cand-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand-a");

    BOOST_REQUIRE(plane.Stage("cand-b", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand-b");
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.blocks(), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
