// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promotegate/promotegate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_promotegate_realm_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bytes_moved_stay_zero)
{
    modelnet::SwarmPromoteGate plane;
    std::string err = "prior";

    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.spent());
    BOOST_REQUIRE_EQUAL(plane.active(), "base");

    BOOST_REQUIRE(plane.Begin("next", err));
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.mined());

    BOOST_REQUIRE(plane.Interrupt(err));
    BOOST_REQUIRE(!plane.Finish(err));
    BOOST_REQUIRE_EQUAL(err, "INTERRUPTED");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.broadcast());

    BOOST_REQUIRE(plane.Clear(err));
    BOOST_REQUIRE(plane.Begin("next", err));
    BOOST_REQUIRE(plane.Finish(err));
    BOOST_REQUIRE_EQUAL(plane.active(), "next");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.spent());

    BOOST_REQUIRE(plane.Rollback(err));
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.spent());
}

BOOST_AUTO_TEST_CASE(realm_refused)
{
    modelnet::SwarmPromoteGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.PromoteRealm(err));
    BOOST_REQUIRE_EQUAL(err, "REALM");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE(plane.previous().empty());
    BOOST_REQUIRE(!plane.interrupted());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(plane.Begin("next", err));
    BOOST_REQUIRE(plane.Interrupt(err));
    const modelnet::SwarmPromoteGate& view = plane;
    BOOST_REQUIRE(!view.PromoteRealm(err));
    BOOST_REQUIRE_EQUAL(err, "REALM");
    BOOST_REQUIRE_EQUAL(plane.active(), "base");
    BOOST_REQUIRE_EQUAL(plane.staged(), "next");
    BOOST_REQUIRE(plane.interrupted());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);

    BOOST_REQUIRE(plane.Clear(err));
    err = "prior";
    BOOST_REQUIRE(plane.Begin("next", err));
    BOOST_REQUIRE(plane.Finish(err));
    const std::string active = plane.active();
    const std::string previous = plane.previous();
    BOOST_REQUIRE(!plane.PromoteRealm(err));
    BOOST_REQUIRE_EQUAL(err, "REALM");
    BOOST_REQUIRE_EQUAL(plane.active(), active);
    BOOST_REQUIRE_EQUAL(plane.previous(), previous);
    BOOST_REQUIRE(plane.staged().empty());
    BOOST_REQUIRE(!plane.interrupted());
    BOOST_REQUIRE(!plane.graduated());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.spent());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
