// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchhold/swarm_watchhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_watchhold_refund_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(margin_stores_nothing)
{
    modelnet::SwarmWatchHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Observe(2, err));
    BOOST_REQUIRE(plane.latest() == 2);

    err = "prior";
    BOOST_REQUIRE(!plane.Refund(100, 259, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE(!plane.refund_noted());
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(plane.noted_height() == 0);
    BOOST_REQUIRE(plane.noted_refund_height() == 0);
    BOOST_REQUIRE(plane.latest() == 2);
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Refund(100, 100, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE(!plane.refund_noted());
    BOOST_REQUIRE(plane.latest() == 2);

    err = "prior";
    BOOST_REQUIRE(!plane.Refund(50, 0, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE(!plane.refund_noted());
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(refund_at_margin_is_held_and_does_not_broadcast)
{
    modelnet::SwarmWatchHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Observe(6, err));
    BOOST_REQUIRE(plane.latest() == 6);
    BOOST_REQUIRE(!plane.secret_released());

    err = "prior";
    BOOST_REQUIRE(!plane.Refund(100, 260, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.refund_noted());
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(plane.noted_height() == 100);
    BOOST_REQUIRE(plane.noted_refund_height() == 260);
    BOOST_REQUIRE(plane.latest() == 6);
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Refund(100, 261, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.noted_height() == 100);
    BOOST_REQUIRE(plane.noted_refund_height() == 261);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.latest() == 6);

    err = "prior";
    BOOST_REQUIRE(!plane.Refund(100, 259, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE(plane.noted_height() == 100);
    BOOST_REQUIRE(plane.noted_refund_height() == 261);
    BOOST_REQUIRE(plane.refund_noted());
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(plane.latest() == 6);
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(refund_before_observe_stores_nothing)
{
    modelnet::SwarmWatchHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Refund(10, 169, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE(!plane.refund_noted());
    BOOST_REQUIRE(!plane.observed());
    BOOST_REQUIRE(plane.latest() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Refund(10, 170, err));
    BOOST_REQUIRE_EQUAL(err, "SEQUENCE");
    BOOST_REQUIRE(!plane.refund_noted());
    BOOST_REQUIRE(plane.noted_height() == 0);
    BOOST_REQUIRE(plane.noted_refund_height() == 0);
    BOOST_REQUIRE(!plane.observed());
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    BOOST_REQUIRE(plane.Observe(1, err));
    BOOST_REQUIRE(err.empty());
    err = "prior";
    BOOST_REQUIRE(!plane.Refund(10, 170, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.refund_noted());
    BOOST_REQUIRE(plane.noted_height() == 10);
    BOOST_REQUIRE(plane.noted_refund_height() == 170);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.latest() == 1);
}

BOOST_AUTO_TEST_CASE(margin_near_int64_max_stores_nothing)
{
    modelnet::SwarmWatchHold plane;
    std::string err = "prior";
    const int64_t kMax = std::numeric_limits<int64_t>::max();

    BOOST_REQUIRE(plane.Observe(12, err));

    err = "prior";
    BOOST_REQUIRE(!plane.Refund(kMax - 159, kMax, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE(!plane.refund_noted());
    BOOST_REQUIRE(plane.latest() == 12);
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Refund(kMax - 160, kMax, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.refund_noted());
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(plane.noted_height() == kMax - 160);
    BOOST_REQUIRE(plane.noted_refund_height() == kMax);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(plane.latest() == 12);

    err = "prior";
    BOOST_REQUIRE(!plane.Refund(kMax, kMax, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE(plane.noted_height() == kMax - 160);
    BOOST_REQUIRE(plane.noted_refund_height() == kMax);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.latest() == 12);
}

BOOST_AUTO_TEST_CASE(held_refund_does_not_release_secret_on_replay)
{
    modelnet::SwarmWatchHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Observe(3, err));
    BOOST_REQUIRE(!plane.Refund(20, 180, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");

    err = "prior";
    BOOST_REQUIRE(!plane.Observe(3, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(!plane.Observe(1, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(!plane.Release(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");

    BOOST_REQUIRE(plane.latest() == 3);
    BOOST_REQUIRE(plane.noted_height() == 20);
    BOOST_REQUIRE(plane.noted_refund_height() == 180);
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(!plane.secret_released());
    BOOST_REQUIRE(plane.secret_bytes() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
