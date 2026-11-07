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

BOOST_FIXTURE_TEST_SUITE(swarm_onechannel_quote_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_pool_is_pool)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_REQUIRE(book.BindPool("pool-a", err));
    BOOST_CHECK(!book.Quote("pool-missing", "12.50", err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK(book.quote_of("pool-missing").empty());
    BOOST_CHECK(book.quote_of("pool-a").empty());
    BOOST_CHECK(!book.holds_money("pool-a"));
    ExpectClosed(book);
}

BOOST_AUTO_TEST_CASE(empty_usd_is_quote)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_REQUIRE(book.BindPool("pool-a", err));
    BOOST_CHECK(!book.Quote("pool-a", "", err));
    BOOST_CHECK_EQUAL(err, "QUOTE");
    BOOST_CHECK(book.quote_of("pool-a").empty());
    BOOST_CHECK(!book.holds_money("pool-a"));
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    ExpectClosed(book);
}

BOOST_AUTO_TEST_CASE(quote_is_not_balance_and_holds_money_stays_false)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_REQUIRE(book.BindPool("pool-a", err));
    BOOST_REQUIRE(book.BindPool("pool-b", err));
    BOOST_CHECK(!book.holds_money("pool-a"));

    BOOST_CHECK(!book.Quote("pool-a", "12.50", err));
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
    BOOST_CHECK_EQUAL(book.quote_of("pool-a"), "12.50");
    BOOST_CHECK(!book.holds_money("pool-a"));
    BOOST_CHECK(!book.funded("pool-a"));
    BOOST_CHECK(book.quote_of("pool-b").empty());
    BOOST_CHECK(!book.holds_money("pool-b"));
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    ExpectClosed(book);
}

BOOST_AUTO_TEST_CASE(quote_after_fund_keeps_holds_money)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_REQUIRE(book.BindPool("pool-a", err));
    BOOST_REQUIRE(book.Fund("pool-a", true, err));
    BOOST_CHECK(book.holds_money("pool-a"));

    BOOST_CHECK(!book.Quote("pool-a", "13.00", err));
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
    BOOST_CHECK_EQUAL(book.quote_of("pool-a"), "13.00");
    BOOST_CHECK(book.holds_money("pool-a"));
    BOOST_CHECK(book.funded("pool-a"));
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.broadcast());
    ExpectClosed(book);

    BOOST_CHECK(!book.Quote("pool-a", "", err));
    BOOST_CHECK_EQUAL(err, "QUOTE");
    BOOST_CHECK_EQUAL(book.quote_of("pool-a"), "13.00");
    BOOST_CHECK(book.holds_money("pool-a"));
    ExpectClosed(book);
}

BOOST_AUTO_TEST_SUITE_END()
