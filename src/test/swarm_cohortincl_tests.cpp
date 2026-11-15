// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cohortincl.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cohortincl_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_member_is_member)
{
    modelnet::SwarmCohortIncl cohort;
    std::string err = "prior";
    BOOST_CHECK(!cohort.Admit("", 100, 200, err));
    BOOST_CHECK_EQUAL(err, "MEMBER");
    BOOST_CHECK(!cohort.admitted(""));
    BOOST_CHECK(!cohort.mined());
}

BOOST_AUTO_TEST_CASE(negative_now_is_range)
{
    modelnet::SwarmCohortIncl cohort;
    std::string err = "prior";
    BOOST_CHECK(!cohort.Admit("member-a", -1, 200, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK(!cohort.admitted("member-a"));

    err = "prior";
    BOOST_CHECK(!cohort.Admit("member-b", 100, -1, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK(!cohort.admitted("member-b"));
    BOOST_CHECK(!cohort.mined());
}

BOOST_AUTO_TEST_CASE(lease_until_equal_now_is_admitted)
{
    modelnet::SwarmCohortIncl cohort;
    std::string err = "prior";
    const int64_t now_ms = 1000;
    BOOST_REQUIRE(cohort.Admit("member-a", now_ms, now_ms, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(cohort.admitted("member-a"));
    BOOST_CHECK(!cohort.mined());
}

BOOST_AUTO_TEST_CASE(lease_until_one_before_now_is_expired)
{
    modelnet::SwarmCohortIncl cohort;
    std::string err = "prior";
    const int64_t now_ms = 1000;
    BOOST_CHECK(!cohort.Admit("member-a", now_ms, now_ms - 1, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK(!cohort.admitted("member-a"));
    BOOST_CHECK(!cohort.mined());
}

BOOST_AUTO_TEST_CASE(lease_until_after_now_is_admitted)
{
    modelnet::SwarmCohortIncl cohort;
    std::string err = "prior";
    const int64_t now_ms = 1000;
    BOOST_REQUIRE(cohort.Admit("member-a", now_ms, now_ms + 1, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(cohort.admitted("member-a"));
    BOOST_CHECK(!cohort.mined());
}

BOOST_AUTO_TEST_CASE(duplicate_member_is_replay_and_stays_admitted)
{
    modelnet::SwarmCohortIncl cohort;
    std::string err = "prior";
    BOOST_REQUIRE(cohort.Admit("member-a", 100, 200, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!cohort.Admit("member-a", 150, 250, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(cohort.admitted("member-a"));
    BOOST_CHECK(!cohort.mined());
}

BOOST_AUTO_TEST_CASE(mined_stays_false)
{
    modelnet::SwarmCohortIncl fresh;
    BOOST_CHECK(!fresh.mined());

    modelnet::SwarmCohortIncl cohort;
    std::string err;
    BOOST_REQUIRE(cohort.Admit("member-a", 1, 1, err));
    BOOST_CHECK(!cohort.mined());
    BOOST_CHECK(!cohort.Admit("", 1, 2, err));
    BOOST_CHECK(!cohort.mined());
    BOOST_CHECK(!cohort.Admit("member-b", 5, 4, err));
    BOOST_CHECK(!cohort.mined());
}

BOOST_AUTO_TEST_SUITE_END()
