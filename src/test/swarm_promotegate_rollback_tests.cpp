// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promotegate/promotegate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_promotegate_rollback_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_rollback)
{
    modelnet::SwarmPromoteGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Rollback(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(plane.Begin("next", err));
    BOOST_REQUIRE(plane.Finish(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "next");
    BOOST_REQUIRE_EQUAL(plane.previous(), "base");
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE(!plane.interrupted());

    err = "prior";
    BOOST_REQUIRE(plane.Begin("side", err));
    BOOST_REQUIRE(plane.Rollback(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE_EQUAL(plane.staged(), "side");
    BOOST_REQUIRE(!plane.interrupted());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.spent());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Rollback(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE_EQUAL(plane.staged(), "side");
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(rollback_after_two_finishes_restores_one_id)
{
    modelnet::SwarmPromoteGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Begin("next", err));
    BOOST_REQUIRE(plane.Finish(err));
    BOOST_REQUIRE(plane.Begin("later", err));
    BOOST_REQUIRE(plane.Finish(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "later");
    BOOST_REQUIRE_EQUAL(plane.previous(), "next");
    BOOST_REQUIRE(plane.staged().empty());

    BOOST_REQUIRE(plane.Rollback(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "next");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());

    err = "prior";
    BOOST_REQUIRE(!plane.Rollback(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "next");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(rollback_leaves_an_interrupted_candidate)
{
    modelnet::SwarmPromoteGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Begin("next", err));
    BOOST_REQUIRE(plane.Finish(err));
    BOOST_REQUIRE(plane.Begin("side", err));
    BOOST_REQUIRE(plane.Interrupt(err));
    BOOST_REQUIRE(plane.Rollback(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE_EQUAL(plane.staged(), "side");
    BOOST_REQUIRE(plane.interrupted());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Finish(err));
    BOOST_REQUIRE_EQUAL(err, "INTERRUPTED");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE_EQUAL(plane.staged(), "side");

    err = "prior";
    BOOST_REQUIRE(!plane.Rollback(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.interrupted());
}

BOOST_AUTO_TEST_CASE(a_later_finish_can_arm_rollback_again)
{
    modelnet::SwarmPromoteGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Begin("next", err));
    BOOST_REQUIRE(plane.Finish(err));
    BOOST_REQUIRE(plane.Rollback(err));
    BOOST_REQUIRE_EQUAL(plane.active(), "base");

    err = "prior";
    BOOST_REQUIRE(plane.Begin("later", err));
    BOOST_REQUIRE(plane.Finish(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "later");
    BOOST_REQUIRE_EQUAL(plane.previous(), "base");

    BOOST_REQUIRE(plane.Rollback(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Rollback(err));
    BOOST_REQUIRE_EQUAL(err, "ROLLBACK");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
}

BOOST_AUTO_TEST_SUITE_END()
