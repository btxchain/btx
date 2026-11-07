// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quotefiat/limits.h>
#include <modelnet/swarm_quotefiat/swarm_quotefiat.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void RequireQuiet(const modelnet::SwarmQuoteFiat& plane)
{
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.broadcast() == modelnet::kSwarmQuoteFiatBroadcast);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.mined() == modelnet::kSwarmQuoteFiatMined);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmQuoteFiatBytesMoved);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), modelnet::kSwarmQuoteFiatAutomaticSpend);
    BOOST_REQUIRE(plane.atoms() == 0);
    BOOST_REQUIRE(!plane.usd_is_balance());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_quotefiat_quiet_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(broadcast_mined_bytes_and_spend_stay_fixed)
{
    modelnet::SwarmQuoteFiat plane;
    std::string err = "prior";

    RequireQuiet(plane);

    BOOST_REQUIRE(!plane.Quote("", err));
    BOOST_REQUIRE_EQUAL(err, "QUOTE");
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Quote("19.99", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_BALANCE");
    BOOST_REQUIRE(plane.quoted("19.99"));
    BOOST_REQUIRE(plane.stored_usd("19.99") == "19.99");
    BOOST_REQUIRE(plane.atoms() == 0);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Quote("19.99", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_usd("19.99") == "19.99");
    BOOST_REQUIRE(plane.quote_count() == 1);
    BOOST_REQUIRE(plane.atoms() == 0);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Quote("4.00", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_BALANCE");
    BOOST_REQUIRE(plane.stored_usd("4.00") == "4.00");
    BOOST_REQUIRE(plane.stored_usd("19.99") == "19.99");
    BOOST_REQUIRE(plane.quote_count() == 2);
    RequireQuiet(plane);
}

BOOST_AUTO_TEST_SUITE_END()
