// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cohortexp.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cohortexp_tests, BasicTestingSetup)

static modelnet::SwarmCohortExpiry OpenNote()
{
    modelnet::SwarmCohortExpiry note;
    note.cohort_id = "cohort-a";
    note.now_ms = 10;
    note.until_ms = 20;
    note.want_admit = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_cohort_or_bad_clock_is_cohort)
{
    std::string err = "prior";
    modelnet::SwarmCohortExpiry missing = OpenNote();
    missing.cohort_id.clear();
    missing.want_admit = true;
    const modelnet::SwarmCohortExpiryResult no_id = modelnet::SwarmNoteCohortExpiry(missing, err);
    BOOST_CHECK(!no_id.admitted);
    BOOST_CHECK(!no_id.expired);
    BOOST_CHECK_EQUAL(no_id.code, "COHORT");
    BOOST_CHECK_EQUAL(err, "COHORT");

    modelnet::SwarmCohortExpiry negative_now = OpenNote();
    negative_now.now_ms = -1;
    negative_now.want_admit = true;
    const modelnet::SwarmCohortExpiryResult bad_now = modelnet::SwarmNoteCohortExpiry(negative_now, err);
    BOOST_CHECK(!bad_now.admitted);
    BOOST_CHECK(!bad_now.expired);
    BOOST_CHECK_EQUAL(bad_now.code, "COHORT");
    BOOST_CHECK_EQUAL(err, "COHORT");

    modelnet::SwarmCohortExpiry zero_until = OpenNote();
    zero_until.until_ms = 0;
    zero_until.now_ms = 0;
    zero_until.want_admit = true;
    const modelnet::SwarmCohortExpiryResult bad_until = modelnet::SwarmNoteCohortExpiry(zero_until, err);
    BOOST_CHECK(!bad_until.admitted);
    BOOST_CHECK(!bad_until.expired);
    BOOST_CHECK_EQUAL(bad_until.code, "COHORT");
    BOOST_CHECK_EQUAL(err, "COHORT");

    modelnet::SwarmCohortExpiry negative_until = OpenNote();
    negative_until.until_ms = -3;
    negative_until.now_ms = 5;
    const modelnet::SwarmCohortExpiryResult neg_until = modelnet::SwarmNoteCohortExpiry(negative_until, err);
    BOOST_CHECK(!neg_until.admitted);
    BOOST_CHECK(!neg_until.expired);
    BOOST_CHECK_EQUAL(neg_until.code, "COHORT");
    BOOST_CHECK_EQUAL(err, "COHORT");
}

BOOST_AUTO_TEST_CASE(now_at_or_after_until_is_expired_even_when_admit_is_requested)
{
    std::string err = "prior";
    modelnet::SwarmCohortExpiry equal = OpenNote();
    equal.now_ms = 20;
    equal.until_ms = 20;
    equal.want_admit = true;
    const modelnet::SwarmCohortExpiryResult at_until = modelnet::SwarmNoteCohortExpiry(equal, err);
    BOOST_CHECK(!at_until.admitted);
    BOOST_CHECK(at_until.expired);
    BOOST_CHECK_EQUAL(at_until.code, "EXPIRED");
    BOOST_CHECK_EQUAL(err, "EXPIRED");

    modelnet::SwarmCohortExpiry past = OpenNote();
    past.now_ms = 21;
    past.until_ms = 20;
    past.want_admit = true;
    const modelnet::SwarmCohortExpiryResult after = modelnet::SwarmNoteCohortExpiry(past, err);
    BOOST_CHECK(!after.admitted);
    BOOST_CHECK(after.expired);
    BOOST_CHECK_EQUAL(after.code, "EXPIRED");
    BOOST_CHECK_EQUAL(err, "EXPIRED");
}

BOOST_AUTO_TEST_CASE(want_admit_before_until_is_held)
{
    std::string err = "prior";
    modelnet::SwarmCohortExpiry note = OpenNote();
    note.now_ms = note.until_ms - 1;
    note.want_admit = true;
    const modelnet::SwarmCohortExpiryResult result = modelnet::SwarmNoteCohortExpiry(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.expired);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(one_millisecond_before_until_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmCohortExpiry note = OpenNote();
    note.now_ms = note.until_ms - 1;
    note.want_admit = false;
    const modelnet::SwarmCohortExpiryResult result = modelnet::SwarmNoteCohortExpiry(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.expired);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
