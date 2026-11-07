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

BOOST_FIXTURE_TEST_SUITE(swarm_onechannel_reserve_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_stores_nothing)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_CHECK(!book.Reserve("", err));
    BOOST_CHECK_EQUAL(err, "CHANNEL");
    BOOST_CHECK(book.channel_id().empty());
    BOOST_CHECK_EQUAL(book.pool_count(), static_cast<std::size_t>(0));
    ExpectClosed(book);
}

BOOST_AUTO_TEST_CASE(first_channel_is_stored_and_network_stays_closed)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.channel_id(), "ch-1");
    ExpectClosed(book);
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_same_id)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_CHECK(!book.Reserve("ch-1", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.channel_id(), "ch-1");
    ExpectClosed(book);
}

BOOST_AUTO_TEST_CASE(second_channel_is_not_opened_and_first_id_stays)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_CHECK(!book.Reserve("ch-2", err));
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
    BOOST_CHECK_EQUAL(book.channel_id(), "ch-1");
    BOOST_CHECK(!book.network_opened());
    ExpectClosed(book);

    BOOST_CHECK(!book.Reserve("", err));
    BOOST_CHECK_EQUAL(err, "CHANNEL");
    BOOST_CHECK_EQUAL(book.channel_id(), "ch-1");
    BOOST_CHECK(!book.Reserve("ch-1", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.channel_id(), "ch-1");
    ExpectClosed(book);
}

BOOST_AUTO_TEST_SUITE_END()
