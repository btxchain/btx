// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stagehead/stagehead.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_stagehead_stage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stage_without_adopt)
{
    modelnet::SwarmStageHead plane;
    std::string err = "prior";

    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    BOOST_REQUIRE(plane.Stage("cand", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.spent());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_candidate_stores_nothing)
{
    modelnet::SwarmStageHead plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Stage("", err));
    BOOST_REQUIRE_EQUAL(err, "HEAD");
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());

    err = "prior";
    BOOST_REQUIRE(plane.Stage("cand", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Stage("", err));
    BOOST_REQUIRE_EQUAL(err, "HEAD");
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
}

BOOST_AUTO_TEST_CASE(second_stage_replaces_only_the_candidate)
{
    modelnet::SwarmStageHead plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Stage("cand", err));
    BOOST_REQUIRE(plane.Stage("replacement", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.staged(), "replacement");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());

    BOOST_REQUIRE(plane.Adopt(true, err));
    BOOST_REQUIRE_EQUAL(plane.active(), "replacement");
    BOOST_REQUIRE_EQUAL(plane.previous(), "base");

    err = "prior";
    BOOST_REQUIRE(plane.Stage("later", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.staged(), "later");
    BOOST_REQUIRE_EQUAL(plane.active(), "replacement");
    BOOST_REQUIRE_EQUAL(plane.previous(), "base");
    BOOST_REQUIRE(!plane.graduated());
}

BOOST_AUTO_TEST_SUITE_END()
