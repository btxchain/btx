// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_debitcap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_debitcap_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(open_debit_leaves_remaining_and_short_is_refused)
{
    modelnet::SwarmDebitCap cap;
    std::string err = "stale";

    BOOST_CHECK_EQUAL(cap.Remaining("channel-a"), -1);

    BOOST_REQUIRE(cap.Open("channel-a", 1000, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cap.Remaining("channel-a"), 1000);

    BOOST_REQUIRE(cap.Debit("channel-a", 400, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cap.Remaining("channel-a"), 600);

    BOOST_CHECK(!cap.Debit("channel-a", 700, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK_EQUAL(cap.Remaining("channel-a"), 600);
}

BOOST_AUTO_TEST_CASE(open_and_debit_refusals_leave_remaining)
{
    modelnet::SwarmDebitCap cap;
    std::string err = "stale";

    BOOST_CHECK(!cap.Open("", 1000, err));
    BOOST_CHECK_EQUAL(err, "CHANNEL");
    BOOST_CHECK_EQUAL(cap.Remaining(""), -1);

    BOOST_CHECK(!cap.Open("channel-a", 0, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(cap.Remaining("channel-a"), -1);

    BOOST_CHECK(!cap.Open("channel-a", -1, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(cap.Remaining("channel-a"), -1);

    BOOST_REQUIRE(cap.Open("channel-a", 1000, err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!cap.Open("channel-a", 500, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(cap.Remaining("channel-a"), 1000);

    BOOST_CHECK(!cap.Debit("missing", 1, err));
    BOOST_CHECK_EQUAL(err, "CHANNEL");
    BOOST_CHECK_EQUAL(cap.Remaining("missing"), -1);
    BOOST_CHECK_EQUAL(cap.Remaining("channel-a"), 1000);

    BOOST_CHECK(!cap.Debit("channel-a", 0, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(cap.Remaining("channel-a"), 1000);

    BOOST_CHECK(!cap.Debit("channel-a", -4, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(cap.Remaining("channel-a"), 1000);

    BOOST_REQUIRE(cap.Debit("channel-a", 1000, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cap.Remaining("channel-a"), 0);

    BOOST_CHECK(!cap.Debit("channel-a", 1, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK_EQUAL(cap.Remaining("channel-a"), 0);
}

BOOST_AUTO_TEST_SUITE_END()
