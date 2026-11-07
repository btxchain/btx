// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quotefiat/swarm_quotefiat.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_quotefiat_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_quote_of_the_same_usd_is_replay)
{
    modelnet::SwarmQuoteFiat plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Quote("19.99", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_BALANCE");
    BOOST_REQUIRE(plane.quoted("19.99"));
    BOOST_REQUIRE(plane.stored_usd("19.99") == "19.99");
    BOOST_REQUIRE(plane.atoms() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Quote("19.99", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.quoted("19.99"));
    BOOST_REQUIRE(plane.stored_usd("19.99") == "19.99");
    BOOST_REQUIRE(plane.quote_count() == 1);
    BOOST_REQUIRE(plane.atoms() == 0);
    BOOST_REQUIRE(!plane.usd_is_balance());

    err = "prior";
    BOOST_REQUIRE(!plane.Quote("19.99", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_usd("19.99") == "19.99");
    BOOST_REQUIRE(plane.quote_count() == 1);
    BOOST_REQUIRE(plane.atoms() == 0);
}

BOOST_AUTO_TEST_CASE(empty_usd_is_quote_before_replay)
{
    modelnet::SwarmQuoteFiat plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Quote("19.99", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_BALANCE");

    err = "prior";
    BOOST_REQUIRE(!plane.Quote("", err));
    BOOST_REQUIRE_EQUAL(err, "QUOTE");
    BOOST_REQUIRE(plane.stored_usd("19.99") == "19.99");
    BOOST_REQUIRE(plane.quote_count() == 1);
    BOOST_REQUIRE(plane.atoms() == 0);
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_quote_when_another_usd_is_stored)
{
    modelnet::SwarmQuoteFiat plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Quote("19.99", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_BALANCE");

    err = "prior";
    BOOST_REQUIRE(!plane.Quote("4.00", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_BALANCE");

    err = "prior";
    BOOST_REQUIRE(!plane.Quote("19.99", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_usd("19.99") == "19.99");
    BOOST_REQUIRE(plane.stored_usd("4.00") == "4.00");
    BOOST_REQUIRE(plane.quote_count() == 2);
    BOOST_REQUIRE(plane.atoms() == 0);
    BOOST_REQUIRE(!plane.usd_is_balance());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
