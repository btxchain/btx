// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rotgate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_rotgate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(rotation_requires_two_different_holdouts)
{
    modelnet::SwarmRotGate gate;
    std::string err{"stale"};

    BOOST_CHECK(!gate.Record("", "h1", true, err));
    BOOST_CHECK_EQUAL(err, "REPORT");
    BOOST_CHECK_EQUAL(gate.accepted(), 0);
    BOOST_CHECK(!gate.rotated());

    BOOST_CHECK(!gate.Record("r-fixed", "h1", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_ROTATING");
    BOOST_CHECK_EQUAL(gate.accepted(), 0);
    BOOST_CHECK(!gate.rotated());

    BOOST_REQUIRE(gate.Record("r1", "h1", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gate.accepted(), 1);
    BOOST_CHECK(!gate.rotated());

    BOOST_REQUIRE(gate.Record("r2", "h1", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gate.accepted(), 2);
    BOOST_CHECK(!gate.rotated());

    BOOST_REQUIRE(gate.Record("r3", "h2", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gate.rotated());
    BOOST_CHECK_EQUAL(gate.accepted(), 3);

    BOOST_CHECK(!gate.Record("r1", "h9", true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(gate.accepted(), 3);
    BOOST_CHECK(gate.rotated());
}

BOOST_AUTO_TEST_SUITE_END()
