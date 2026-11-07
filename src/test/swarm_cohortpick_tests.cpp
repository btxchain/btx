// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cohortpick.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cohortpick_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(expired_lease_stores_nothing)
{
    modelnet::SwarmCohortPick pick;
    std::string err = "prior";
    BOOST_CHECK(!pick.Admit("member-a", 1000, 1000, true, true, err));
    BOOST_CHECK_EQUAL(err, "LEASE_EXPIRED");
    BOOST_CHECK(!pick.Contains("member-a"));
    BOOST_CHECK_EQUAL(pick.size(), 0U);
}

BOOST_AUTO_TEST_CASE(checkpoint_mismatch_stores_nothing)
{
    modelnet::SwarmCohortPick pick;
    std::string err = "prior";
    BOOST_CHECK(!pick.Admit("member-a", 100, 1000, false, true, err));
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
    BOOST_CHECK(!pick.Contains("member-a"));
    BOOST_CHECK_EQUAL(pick.size(), 0U);
}

BOOST_AUTO_TEST_CASE(successful_admit_stores_the_member)
{
    modelnet::SwarmCohortPick pick;
    std::string err = "prior";
    BOOST_REQUIRE(pick.Admit("member-a", 100, 1000, true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(pick.Contains("member-a"));
    BOOST_CHECK(!pick.Contains("member-b"));
    BOOST_CHECK_EQUAL(pick.size(), 1U);
}

BOOST_AUTO_TEST_CASE(replay_does_not_store_again)
{
    modelnet::SwarmCohortPick pick;
    std::string err;
    BOOST_REQUIRE(pick.Admit("member-a", 100, 1000, true, true, err));
    BOOST_CHECK(!pick.Admit("member-a", 200, 1000, true, true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(pick.Contains("member-a"));
    BOOST_CHECK_EQUAL(pick.size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
