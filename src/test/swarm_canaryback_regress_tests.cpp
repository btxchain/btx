// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryback/canaryback.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_canaryback_regress_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(regress_before_adopt_is_stage)
{
    modelnet::SwarmCanaryBack plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Regress(err));
    BOOST_REQUIRE_EQUAL(err, "STAGE");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.staged().empty());

    BOOST_REQUIRE(plane.Stage("cand-a", err));
    BOOST_REQUIRE(err.empty());
    err = "prior";
    BOOST_REQUIRE(!plane.Regress(err));
    BOOST_REQUIRE_EQUAL(err, "STAGE");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand-a");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(one_regress_restores_previous_and_second_is_rollback)
{
    modelnet::SwarmCanaryBack plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Stage("cand-a", err));
    BOOST_REQUIRE(plane.Adopt(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "cand-a");

    err = "prior";
    BOOST_REQUIRE(!plane.Adopt(err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.active(), "cand-a");

    err = "prior";
    BOOST_REQUIRE(plane.Regress(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.staged().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Regress(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.staged().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Adopt(err));
    BOOST_REQUIRE_EQUAL(err, "STAGE");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(second_regress_leaves_a_new_unadopted_stage)
{
    modelnet::SwarmCanaryBack plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Stage("cand-a", err));
    BOOST_REQUIRE(plane.Adopt(err));
    BOOST_REQUIRE(plane.Regress(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");

    BOOST_REQUIRE(plane.Stage("cand-b", err));
    BOOST_REQUIRE(err.empty());
    err = "prior";
    BOOST_REQUIRE(!plane.Regress(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand-b");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(newer_adopt_arms_one_more_regress)
{
    modelnet::SwarmCanaryBack plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Stage("cand-a", err));
    BOOST_REQUIRE(plane.Adopt(err));
    BOOST_REQUIRE(plane.Regress(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(!plane.Regress(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");

    BOOST_REQUIRE(plane.Stage("cand-b", err));
    BOOST_REQUIRE(plane.Adopt(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "cand-b");
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand-b");

    err = "prior";
    BOOST_REQUIRE(plane.Regress(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.staged().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Regress(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
}

BOOST_AUTO_TEST_CASE(regress_restores_one_level)
{
    modelnet::SwarmCanaryBack plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Stage("cand-a", err));
    BOOST_REQUIRE(plane.Adopt(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "cand-a");

    BOOST_REQUIRE(plane.Stage("cand-b", err));
    BOOST_REQUIRE(plane.Adopt(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "cand-b");

    err = "prior";
    BOOST_REQUIRE(plane.Regress(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "cand-a");
    BOOST_REQUIRE(plane.staged().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Regress(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "cand-a");
    BOOST_REQUIRE_EQUAL(plane.blocks(), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
