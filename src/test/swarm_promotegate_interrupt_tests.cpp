// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promotegate/promotegate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_promotegate_interrupt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(interrupt_without_begin_is_step)
{
    modelnet::SwarmPromoteGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Interrupt(err));
    BOOST_REQUIRE_EQUAL(err, "STEP");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE(!plane.interrupted());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Finish(err));
    BOOST_REQUIRE_EQUAL(err, "STEP");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(!plane.interrupted());
}

BOOST_AUTO_TEST_CASE(interrupt_before_finish)
{
    modelnet::SwarmPromoteGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Begin("cand", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Interrupt(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.interrupted());
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.spent());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Finish(err));
    BOOST_REQUIRE_EQUAL(err, "INTERRUPTED");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand");
    BOOST_REQUIRE(plane.interrupted());
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Finish(err));
    BOOST_REQUIRE_EQUAL(err, "INTERRUPTED");
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.interrupted());
}

BOOST_AUTO_TEST_CASE(second_interrupt_stays_marked)
{
    modelnet::SwarmPromoteGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Begin("cand", err));
    BOOST_REQUIRE(plane.Interrupt(err));
    err = "prior";
    BOOST_REQUIRE(plane.Interrupt(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.interrupted());
    BOOST_REQUIRE_EQUAL(plane.staged(), "cand");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(!plane.mined());
}

BOOST_AUTO_TEST_CASE(interrupt_after_clear_stores_nothing)
{
    modelnet::SwarmPromoteGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Begin("cand", err));
    BOOST_REQUIRE(plane.Interrupt(err));
    BOOST_REQUIRE(plane.Clear(err));
    BOOST_REQUIRE(!plane.interrupted());
    BOOST_REQUIRE(plane.staged().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Interrupt(err));
    BOOST_REQUIRE_EQUAL(err, "STEP");
    BOOST_REQUIRE(!plane.interrupted());
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(interrupt_after_finish_stores_nothing)
{
    modelnet::SwarmPromoteGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Begin("next", err));
    BOOST_REQUIRE(plane.Finish(err));
    BOOST_REQUIRE_EQUAL(plane.active(), "next");
    BOOST_REQUIRE(plane.staged().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Interrupt(err));
    BOOST_REQUIRE_EQUAL(err, "STEP");
    BOOST_REQUIRE(!plane.interrupted());
    BOOST_REQUIRE_EQUAL(plane.active(), "next");
    BOOST_REQUIRE_EQUAL(plane.previous(), "base");
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE(!plane.graduated());
}

BOOST_AUTO_TEST_SUITE_END()
