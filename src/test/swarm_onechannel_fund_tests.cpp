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

BOOST_FIXTURE_TEST_SUITE(swarm_onechannel_fund_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_pool_stays_unfunded)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_REQUIRE(book.BindPool("pool-a", err));
    BOOST_CHECK(!book.Fund("pool-missing", true, err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK(!book.funded("pool-missing"));
    BOOST_CHECK(!book.holds_money("pool-missing"));
    BOOST_CHECK(!book.funded("pool-a"));
    BOOST_CHECK(!book.holds_money("pool-a"));
    ExpectClosed(book);
}

BOOST_AUTO_TEST_CASE(unfunded_pool_does_not_hold_money)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_REQUIRE(book.BindPool("pool-a", err));
    BOOST_REQUIRE(book.BindPool("pool-b", err));

    BOOST_CHECK(!book.funded("pool-a"));
    BOOST_CHECK(!book.holds_money("pool-a"));
    BOOST_CHECK(!book.funded("pool-b"));
    BOOST_CHECK(!book.holds_money("pool-b"));

    BOOST_CHECK(!book.Fund("pool-a", false, err));
    BOOST_CHECK_EQUAL(err, "FUNDING");
    BOOST_CHECK(!book.funded("pool-a"));
    BOOST_CHECK(!book.holds_money("pool-a"));
    BOOST_CHECK(!book.funded("pool-b"));
    BOOST_CHECK(!book.holds_money("pool-b"));
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    ExpectClosed(book);
}

BOOST_AUTO_TEST_CASE(funding_one_pool_does_not_fund_the_other)
{
    modelnet::SwarmOneChannel book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Reserve("ch-1", err));
    BOOST_REQUIRE(book.BindPool("pool-a", err));
    BOOST_REQUIRE(book.BindPool("pool-b", err));

    BOOST_REQUIRE(book.Fund("pool-a", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.funded("pool-a"));
    BOOST_CHECK(book.holds_money("pool-a"));
    BOOST_CHECK(!book.funded("pool-b"));
    BOOST_CHECK(!book.holds_money("pool-b"));
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(book.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(book.channel_id(), "ch-1");
    ExpectClosed(book);
}

BOOST_AUTO_TEST_SUITE_END()
