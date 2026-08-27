// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/gbt_longpoll.h>

#include <atomic>
#include <chrono>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(gbt_longpoll_tests)

BOOST_AUTO_TEST_CASE(waiter_cap_is_rpcthreads_over_four)
{
    BOOST_CHECK_EQUAL(node::GbtLongPollWaiterCap(1), 1);
    BOOST_CHECK_EQUAL(node::GbtLongPollWaiterCap(3), 1);
    BOOST_CHECK_EQUAL(node::GbtLongPollWaiterCap(4), 1);
    BOOST_CHECK_EQUAL(node::GbtLongPollWaiterCap(16), 4);
    BOOST_CHECK_EQUAL(node::GbtLongPollWaiterCap(128), 32);
}

BOOST_AUTO_TEST_CASE(lifetime_expires_at_sixty_seconds)
{
    const auto start{std::chrono::steady_clock::now()};
    BOOST_CHECK(!node::GbtLongPollLifetimeExpired(start, start + std::chrono::seconds{59}));
    BOOST_CHECK(node::GbtLongPollLifetimeExpired(start, start + std::chrono::seconds{60}));
    BOOST_CHECK(node::GbtLongPollLifetimeExpired(start, start + std::chrono::seconds{61}));
}

BOOST_AUTO_TEST_CASE(waiter_slot_rejects_past_cap)
{
    std::atomic<int> waiters{0};
    node::GbtLongPollWaiterSlot first{waiters, /*cap=*/1};
    node::GbtLongPollWaiterSlot second{waiters, /*cap=*/1};
    BOOST_CHECK(first.TryAcquire());
    BOOST_CHECK(!second.TryAcquire());
}

BOOST_AUTO_TEST_SUITE_END()
