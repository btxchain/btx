// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/unshield_velocity.h>

#include <consensus/amount.h>
#include <streams.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(shielded_unshield_velocity_tests)

namespace {
constexpr uint32_t WIN = 960;     // ~1 day at 90s
constexpr uint32_t BPS = 1000;    // 10% of pool per window
constexpr CAmount POOL = 1000 * COIN;
} // namespace

BOOST_AUTO_TEST_CASE(window_cap_is_pct_of_pool)
{
    BOOST_CHECK_EQUAL(ShieldedUnshieldVelocity::WindowCap(POOL, BPS), 100 * COIN); // 10% of 1000
    BOOST_CHECK_EQUAL(ShieldedUnshieldVelocity::WindowCap(POOL, 0), 0);
    BOOST_CHECK_EQUAL(ShieldedUnshieldVelocity::WindowCap(0, BPS), 0);
    BOOST_CHECK_EQUAL(ShieldedUnshieldVelocity::WindowCap(POOL * 2, BPS), 200 * COIN); // auto-scales
    BOOST_CHECK_EQUAL(ShieldedUnshieldVelocity::WindowCap(POOL, BPS, 250 * COIN), 250 * COIN);
    BOOST_CHECK_EQUAL(ShieldedUnshieldVelocity::WindowCap(0, BPS, 250 * COIN), 250 * COIN);
}

BOOST_AUTO_TEST_CASE(window_sum_and_cap_enforcement)
{
    ShieldedUnshieldVelocity v;
    // Spread egress over the window: 60 + 40 == cap (100), within.
    v.RecordBlock(100, 60 * COIN);
    v.RecordBlock(200, 40 * COIN);
    BOOST_CHECK_EQUAL(v.WindowTotal(200, WIN), 100 * COIN);
    BOOST_CHECK(v.WithinCap(200, POOL, BPS, WIN));
    // One more sat within the same window exceeds the 10% cap.
    v.RecordBlock(300, 1);
    BOOST_CHECK(!v.WithinCap(300, POOL, BPS, WIN));
    BOOST_CHECK(v.WithinCap(300, POOL, BPS, WIN, 101 * COIN));
}

BOOST_AUTO_TEST_CASE(window_boundary_is_exclusive_lower)
{
    ShieldedUnshieldVelocity v;
    v.RecordBlock(10, 50 * COIN);       // exactly window_blocks before tip 970 -> aged out
    v.RecordBlock(500, 30 * COIN);      // inside
    v.RecordBlock(970, 30 * COIN);      // tip
    // window (970-960, 970] = (10, 970]; block 10 is EXCLUDED (boundary exclusive), 970 included.
    BOOST_CHECK_EQUAL(v.WindowTotal(970, WIN), 60 * COIN); // 500 + 970
    // tip 969: window (9, 969] now INCLUDES block 10 (10 > 9) but EXCLUDES 970 (> tip).
    BOOST_CHECK_EQUAL(v.WindowTotal(969, WIN), 80 * COIN); // 10 + 500
}

BOOST_AUTO_TEST_CASE(net_ingress_records_zero)
{
    ShieldedUnshieldVelocity v;
    v.RecordBlock(100, -500 * COIN);    // a shield-in: no egress
    v.RecordBlock(101, 0);
    BOOST_CHECK_EQUAL(v.WindowTotal(101, WIN), 0);
    BOOST_CHECK(v.WithinCap(101, POOL, BPS, WIN));
}

BOOST_AUTO_TEST_CASE(undo_is_exact_reorg_safe)
{
    ShieldedUnshieldVelocity v;
    v.RecordBlock(100, 30 * COIN);
    const CAmount after_100 = v.WindowTotal(100, WIN);
    v.RecordBlock(101, 30 * COIN);
    BOOST_CHECK_EQUAL(v.WindowTotal(101, WIN), 60 * COIN);
    // Disconnect block 101: erasing its entry restores the post-100 view exactly.
    v.UndoBlock(101);
    BOOST_CHECK_EQUAL(v.WindowTotal(100, WIN), after_100);
}

BOOST_AUTO_TEST_CASE(prune_drops_below_floor_only)
{
    ShieldedUnshieldVelocity v;
    for (int h = 1; h <= 2000; ++h) v.RecordBlock(h, 1);
    // Keep only the last window+buffer; prune below 2000-2*WIN.
    v.Prune(2000 - 2 * static_cast<int>(WIN));
    // The trailing window total is unaffected by pruning below it.
    BOOST_CHECK_EQUAL(v.WindowTotal(2000, WIN), static_cast<CAmount>(WIN)); // 960 blocks * 1 sat
}

BOOST_AUTO_TEST_CASE(serialization_round_trips)
{
    ShieldedUnshieldVelocity v;
    v.RecordBlock(123, 7 * COIN);
    v.RecordBlock(456, 3 * COIN);
    DataStream ss;
    ss << v;
    ShieldedUnshieldVelocity v2;
    ss >> v2;
    BOOST_CHECK_EQUAL(v2.WindowTotal(456, WIN), v.WindowTotal(456, WIN));
}

BOOST_AUTO_TEST_SUITE_END()
