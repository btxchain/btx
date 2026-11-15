// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_onechannel/swarm_onechannel.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>

static void ExpectClosed(const modelnet::SwarmOneChannel& book)
{
    BOOST_CHECK(!book.network_opened());
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK(!book.launched());
    BOOST_CHECK(!book.gpu());
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(book.automatic_spend(), "0");
}

BOOST_FIXTURE_TEST_SUITE(swarm_onechannel_bind_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_pool_stores_nothing)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_CHECK(!book.BindPool("", err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK(!book.bound(""));
    BOOST_CHECK_EQUAL(book.pool_count(), static_cast<std::size_t>(0));
    BOOST_CHECK_EQUAL(book.channel_id(), "ch-1");
    ExpectClosed(book);
}

BOOST_AUTO_TEST_CASE(bind_before_reserve_is_channel)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_CHECK(!book.BindPool("pool-a", err));
    BOOST_CHECK_EQUAL(err, "CHANNEL");
    BOOST_CHECK(!book.bound("pool-a"));
    BOOST_CHECK(book.channel_id().empty());
    BOOST_CHECK_EQUAL(book.pool_count(), static_cast<std::size_t>(0));
    ExpectClosed(book);
}

BOOST_AUTO_TEST_CASE(two_pools_share_one_channel)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_REQUIRE(book.BindPool("pool-a", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(book.BindPool("pool-b", err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(book.bound("pool-a"));
    BOOST_CHECK(book.bound("pool-b"));
    BOOST_CHECK_EQUAL(book.pool_count(), static_cast<std::size_t>(2));
    BOOST_CHECK_EQUAL(book.channel_id(), "ch-1");

    BOOST_CHECK(!book.Reserve("ch-2", err));
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
    BOOST_CHECK_EQUAL(book.channel_id(), "ch-1");
    BOOST_CHECK(book.bound("pool-a"));
    BOOST_CHECK(book.bound("pool-b"));
    BOOST_CHECK_EQUAL(book.pool_count(), static_cast<std::size_t>(2));
    ExpectClosed(book);
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_pool)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_REQUIRE(book.BindPool("pool-a", err));
    BOOST_CHECK(!book.BindPool("pool-a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(book.bound("pool-a"));
    BOOST_CHECK_EQUAL(book.pool_count(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(book.channel_id(), "ch-1");
    ExpectClosed(book);
}

BOOST_AUTO_TEST_SUITE_END()
