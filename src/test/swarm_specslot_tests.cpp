// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_specslot.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_specslot_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(open_two_spend_one_refuse_two)
{
    modelnet::SwarmSpecSlot slots;
    std::string err = "prior";

    BOOST_CHECK(!slots.Open("", 2, err));
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_CHECK_EQUAL(slots.Remaining(""), -1);

    BOOST_CHECK(!slots.Open("explore", 0, err));
    BOOST_CHECK_EQUAL(err, "SLOTS");
    BOOST_CHECK_EQUAL(slots.Remaining("explore"), -1);

    BOOST_REQUIRE(slots.Open("explore", 2, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(slots.Remaining("explore"), 2);

    BOOST_CHECK(!slots.Open("explore", 2, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(slots.Remaining("explore"), 2);

    BOOST_CHECK(!slots.Spend("missing", 1, err));
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_CHECK_EQUAL(slots.Remaining("missing"), -1);
    BOOST_CHECK_EQUAL(slots.Remaining("explore"), 2);

    BOOST_CHECK(!slots.Spend("explore", 0, err));
    BOOST_CHECK_EQUAL(err, "SLOTS");
    BOOST_CHECK_EQUAL(slots.Remaining("explore"), 2);

    BOOST_REQUIRE(slots.Spend("explore", 1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(slots.Remaining("explore"), 1);

    BOOST_CHECK(!slots.Spend("explore", 2, err));
    BOOST_CHECK_EQUAL(err, "EXHAUSTED");
    BOOST_CHECK_EQUAL(slots.Remaining("explore"), 1);
}

BOOST_AUTO_TEST_SUITE_END()
