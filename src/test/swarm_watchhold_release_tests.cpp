// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchhold/swarm_watchhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_watchhold_release_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(release_before_observe_is_held_and_stores_no_secret)
{
    modelnet::SwarmWatchHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Release(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(!plane.observed());
    BOOST_REQUIRE(plane.latest() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.refund_noted());
    BOOST_REQUIRE(!plane.refund_built());

    err = "prior";
    BOOST_REQUIRE(!plane.Release(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
}

BOOST_AUTO_TEST_CASE(release_after_observe_stays_held)
{
    modelnet::SwarmWatchHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Observe(4, err));
    BOOST_REQUIRE(plane.latest() == 4);
    BOOST_REQUIRE(!plane.secret_released());

    err = "prior";
    BOOST_REQUIRE(!plane.Release(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(plane.latest() == 4);
    BOOST_REQUIRE(plane.observed());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    BOOST_REQUIRE(plane.Observe(11, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.latest() == 11);

    err = "prior";
    BOOST_REQUIRE(!plane.Observe(11, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(!plane.Release(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.latest() == 11);
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Observe(10, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(!plane.Release(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.latest() == 11);
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.refund_built());
}

BOOST_AUTO_TEST_SUITE_END()
