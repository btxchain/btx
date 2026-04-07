// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <shielded/bundle.h>
#include <shielded/turnstile.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_v2_egress_fixture.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(shielded_turnstile_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(turnstile_shield_increases_balance)
{
    ShieldedPoolBalance pool;
    BOOST_CHECK(pool.ApplyValueBalance(-10 * COIN));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 10 * COIN);
}

BOOST_AUTO_TEST_CASE(turnstile_unshield_decreases_balance)
{
    ShieldedPoolBalance pool;
    BOOST_CHECK(pool.ApplyValueBalance(-10 * COIN));
    BOOST_CHECK(pool.ApplyValueBalance(3 * COIN));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 7 * COIN);
}

BOOST_AUTO_TEST_CASE(turnstile_rejects_negative)
{
    ShieldedPoolBalance pool;
    BOOST_CHECK(!pool.ApplyValueBalance(1 * COIN));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 0);
}

BOOST_AUTO_TEST_CASE(turnstile_undo_roundtrip)
{
    ShieldedPoolBalance pool;
    BOOST_CHECK(pool.ApplyValueBalance(-5 * COIN));
    BOOST_CHECK(pool.ApplyValueBalance(2 * COIN));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 3 * COIN);

    BOOST_CHECK(pool.UndoValueBalance(2 * COIN));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 5 * COIN);

    BOOST_CHECK(pool.UndoValueBalance(-5 * COIN));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 0);
}

BOOST_AUTO_TEST_CASE(turnstile_set_balance_checks_range)
{
    ShieldedPoolBalance pool;
    BOOST_CHECK(pool.SetBalance(42));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 42);

    BOOST_CHECK(!pool.SetBalance(-1));
    BOOST_CHECK(!pool.SetBalance(MAX_MONEY + 1));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 42);
}

// R6-311: Verify MAX_MONEY overflow boundary through shielded pool.
BOOST_AUTO_TEST_CASE(turnstile_rejects_overflow_beyond_max_money)
{
    ShieldedPoolBalance pool;
    // Fill pool to MAX_MONEY
    BOOST_CHECK(pool.ApplyValueBalance(-MAX_MONEY));
    BOOST_CHECK_EQUAL(pool.GetBalance(), MAX_MONEY);

    // One more satoshi should fail
    BOOST_CHECK(!pool.ApplyValueBalance(-1));
    BOOST_CHECK_EQUAL(pool.GetBalance(), MAX_MONEY);
}

BOOST_AUTO_TEST_CASE(turnstile_mixed_family_state_balances_roundtrip)
{
    ShieldedPoolBalance pool;
    BOOST_CHECK(pool.ApplyValueBalance(-(12 * COIN)));

    std::string reject_reason;

    const auto egress_fixture = test::shielded::BuildV2EgressReceiptFixture(/*output_count=*/3);
    const auto egress_state_value =
        TryGetShieldedStateValueBalance(egress_fixture.tx.shielded_bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(egress_state_value.has_value(), reject_reason);

    reject_reason.clear();
    const auto rebalance_fixture = test::shielded::BuildV2RebalanceFixture();
    const auto rebalance_state_value =
        TryGetShieldedStateValueBalance(rebalance_fixture.tx.shielded_bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(rebalance_state_value.has_value(), reject_reason);

    reject_reason.clear();
    const auto settlement_fixture = test::shielded::BuildV2SettlementAnchorReceiptFixture();
    const auto settlement_state_value =
        TryGetShieldedStateValueBalance(settlement_fixture.tx.shielded_bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(settlement_state_value.has_value(), reject_reason);

    BOOST_CHECK(pool.ApplyValueBalance(*egress_state_value));
    BOOST_CHECK(pool.ApplyValueBalance(*rebalance_state_value));
    BOOST_CHECK(pool.ApplyValueBalance(*settlement_state_value));
    BOOST_CHECK(pool.ApplyValueBalance(5 * COIN));

    const CAmount expected_balance =
        12 * COIN - *egress_state_value - *rebalance_state_value - *settlement_state_value - 5 * COIN;
    BOOST_CHECK_EQUAL(pool.GetBalance(), expected_balance);

    BOOST_CHECK(pool.UndoValueBalance(5 * COIN));
    BOOST_CHECK(pool.UndoValueBalance(*settlement_state_value));
    BOOST_CHECK(pool.UndoValueBalance(*rebalance_state_value));
    BOOST_CHECK(pool.UndoValueBalance(*egress_state_value));
    BOOST_CHECK(pool.UndoValueBalance(-(12 * COIN)));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
