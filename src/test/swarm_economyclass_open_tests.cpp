// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_economyclass/swarm_economyclass.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_economyclass_open_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_channel_funds_one_pool_and_does_not_open_a_network)
{
    modelnet::SwarmEconomyClass book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Open("channel-1", "pool-a", "pool-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.holds_money("pool-a"));
    BOOST_CHECK(!book.holds_money("pool-b"));
    BOOST_CHECK(!book.network_opened());
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(book.automatic_spend(), "0");

    BOOST_CHECK(!book.Open("channel-1", "pool-a", "pool-b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(book.holds_money("pool-a"));

    BOOST_CHECK(!book.Open("channel-2", "pool-c", "pool-d", err));
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
    BOOST_CHECK(!book.network_opened());
    BOOST_CHECK(book.holds_money("pool-a"));
    BOOST_CHECK(!book.holds_money("pool-c"));
}

BOOST_AUTO_TEST_SUITE_END()
