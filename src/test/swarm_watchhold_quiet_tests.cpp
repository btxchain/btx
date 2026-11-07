// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchhold/swarm_watchhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_watchhold_quiet_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(broadcast_stays_false)
{
    modelnet::SwarmWatchHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);

    BOOST_REQUIRE(!plane.Observe(0, err));
    BOOST_REQUIRE_EQUAL(err, "SEQUENCE");
    BOOST_REQUIRE(plane.Observe(1, err));
    BOOST_REQUIRE(!plane.Observe(1, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.Observe(4, err));
    BOOST_REQUIRE(!plane.Observe(2, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(!plane.Release(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.Refund(40, 199, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE(!plane.Refund(40, 200, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");

    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(plane.refund_noted());
    BOOST_REQUIRE(plane.latest() == 4);
    BOOST_REQUIRE(plane.noted_height() == 40);
    BOOST_REQUIRE(plane.noted_refund_height() == 200);

    err = "prior";
    BOOST_REQUIRE(!plane.Refund(40, 199, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE(plane.noted_refund_height() == 200);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.secret_released());
}

BOOST_AUTO_TEST_SUITE_END()
