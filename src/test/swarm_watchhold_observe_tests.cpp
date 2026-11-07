// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchhold/swarm_watchhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_watchhold_observe_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sequence_below_one_is_sequence_and_stores_nothing)
{
    modelnet::SwarmWatchHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.latest() == 0);
    BOOST_REQUIRE(!plane.observed());
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);

    BOOST_REQUIRE(!plane.Observe(0, err));
    BOOST_REQUIRE_EQUAL(err, "SEQUENCE");
    BOOST_REQUIRE(plane.latest() == 0);
    BOOST_REQUIRE(!plane.observed());
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Observe(-1, err));
    BOOST_REQUIRE_EQUAL(err, "SEQUENCE");
    BOOST_REQUIRE(plane.latest() == 0);
    BOOST_REQUIRE(!plane.observed());

    err = "prior";
    BOOST_REQUIRE(!plane.Observe(std::numeric_limits<int64_t>::min(), err));
    BOOST_REQUIRE_EQUAL(err, "SEQUENCE");
    BOOST_REQUIRE(plane.latest() == 0);
    BOOST_REQUIRE(!plane.observed());
    BOOST_REQUIRE(!plane.refund_noted());
    BOOST_REQUIRE(!plane.secret_released());
}

BOOST_AUTO_TEST_CASE(greater_sequence_becomes_latest)
{
    modelnet::SwarmWatchHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Observe(1, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.observed());
    BOOST_REQUIRE(plane.latest() == 1);
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    BOOST_REQUIRE(plane.Observe(2, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.latest() == 2);

    BOOST_REQUIRE(plane.Observe(9, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.latest() == 9);
    BOOST_REQUIRE(plane.observed());
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);

    BOOST_REQUIRE(plane.Observe(std::numeric_limits<int64_t>::max(), err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.latest() == std::numeric_limits<int64_t>::max());
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(stale_sequence_does_not_change_latest)
{
    modelnet::SwarmWatchHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Observe(4, err));
    BOOST_REQUIRE(plane.Observe(8, err));
    BOOST_REQUIRE(plane.latest() == 8);

    err = "prior";
    BOOST_REQUIRE(!plane.Observe(7, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(plane.latest() == 8);
    BOOST_REQUIRE(plane.observed());
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Observe(4, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(plane.latest() == 8);

    err = "prior";
    BOOST_REQUIRE(!plane.Observe(1, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(plane.latest() == 8);

    err = "prior";
    BOOST_REQUIRE(!plane.Observe(0, err));
    BOOST_REQUIRE_EQUAL(err, "SEQUENCE");
    BOOST_REQUIRE(plane.latest() == 8);
    BOOST_REQUIRE(!plane.secret_released());

    BOOST_REQUIRE(plane.Observe(9, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.latest() == 9);
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(replay_keeps_latest)
{
    modelnet::SwarmWatchHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Observe(3, err));
    BOOST_REQUIRE(plane.latest() == 3);

    err = "prior";
    BOOST_REQUIRE(!plane.Observe(3, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.latest() == 3);
    BOOST_REQUIRE(plane.observed());
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    BOOST_REQUIRE(plane.Observe(6, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.latest() == 6);

    err = "prior";
    BOOST_REQUIRE(!plane.Observe(6, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.latest() == 6);

    err = "prior";
    BOOST_REQUIRE(!plane.Observe(3, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(plane.latest() == 6);
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(secret_stays_unreleased_after_every_observe)
{
    modelnet::SwarmWatchHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);

    BOOST_REQUIRE(!plane.Observe(0, err));
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);

    BOOST_REQUIRE(plane.Observe(1, err));
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);

    BOOST_REQUIRE(!plane.Observe(1, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(!plane.secret_released());

    BOOST_REQUIRE(plane.Observe(5, err));
    BOOST_REQUIRE(!plane.Observe(2, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(plane.latest() == 5);
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.refund_noted());
    BOOST_REQUIRE(!plane.refund_built());
}

BOOST_AUTO_TEST_SUITE_END()
