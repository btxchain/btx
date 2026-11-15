// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_samplepick.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_samplepick_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(private_kind_stores_nothing)
{
    modelnet::SwarmSamplePick pick;
    std::string err = "prior";
    BOOST_CHECK(!pick.Select("sample-a", "private_prompt", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(pick.Selected().empty());

    BOOST_CHECK(!pick.Select("sample-b", "credential", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(pick.Selected().empty());
}

BOOST_AUTO_TEST_CASE(two_samples_selected_in_order)
{
    modelnet::SwarmSamplePick pick;
    std::string err = "prior";
    BOOST_REQUIRE(pick.Select("sample-a", "public_trajectory", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(pick.Select("sample-b", "synthetic_trajectory", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE_EQUAL(pick.Selected().size(), 2U);
    BOOST_CHECK_EQUAL(pick.Selected()[0], "sample-a");
    BOOST_CHECK_EQUAL(pick.Selected()[1], "sample-b");
}

BOOST_AUTO_TEST_CASE(replay_does_not_store_again)
{
    modelnet::SwarmSamplePick pick;
    std::string err;
    BOOST_REQUIRE(pick.Select("sample-a", "public_trajectory", err));
    BOOST_CHECK(!pick.Select("sample-a", "synthetic_trajectory", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(pick.Selected().size(), 1U);
    BOOST_CHECK_EQUAL(pick.Selected()[0], "sample-a");
}

BOOST_AUTO_TEST_SUITE_END()
