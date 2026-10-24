// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_onechannel/swarm_onechannel.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

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

BOOST_FIXTURE_TEST_SUITE(swarm_onechannel_open_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(open_is_not_opened_with_no_channel)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_CHECK(!book.Open(err));
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
    BOOST_CHECK(!book.network_opened());
    BOOST_CHECK(book.channel_id().empty());
    ExpectClosed(book);
}

BOOST_AUTO_TEST_CASE(reserved_channel_is_not_a_network_open)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_CHECK(!book.Open(err));
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
    BOOST_CHECK(!book.network_opened());
    BOOST_CHECK_EQUAL(book.channel_id(), "ch-1");
    ExpectClosed(book);

    BOOST_CHECK(!book.Open(err));
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
    BOOST_CHECK(!book.network_opened());
    BOOST_CHECK_EQUAL(book.channel_id(), "ch-1");
    ExpectClosed(book);
}

BOOST_AUTO_TEST_CASE(open_after_bind_and_fund_stays_closed)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_REQUIRE(book.BindPool("pool-a", err));
    BOOST_REQUIRE(book.Fund("pool-a", true, err));
    BOOST_CHECK(book.holds_money("pool-a"));

    BOOST_CHECK(!book.Open(err));
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
    BOOST_CHECK(!book.network_opened());
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK_EQUAL(book.channel_id(), "ch-1");
    BOOST_CHECK(book.holds_money("pool-a"));
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    ExpectClosed(book);
}

BOOST_AUTO_TEST_SUITE_END()
