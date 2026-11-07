// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcohort.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notcohort_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_cohort_id_is_cohort)
{
    std::string err = "prior";
    modelnet::SwarmNotCohort note;
    note.now_ms = 10;
    note.until_ms = 20;
    note.want_extend = true;
    const modelnet::SwarmNotCohortResult result = modelnet::SwarmNoteNotCohort(note, err);
    BOOST_CHECK(!result.extended);
    BOOST_CHECK(!result.expired);
    BOOST_CHECK_EQUAL(result.code, "COHORT");
    BOOST_CHECK_EQUAL(err, "COHORT");
}

BOOST_AUTO_TEST_CASE(want_extend_before_until_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotCohort note;
    note.cohort_id = "cohort-a";
    note.now_ms = 10;
    note.until_ms = 20;
    note.want_extend = true;
    const modelnet::SwarmNotCohortResult result = modelnet::SwarmNoteNotCohort(note, err);
    BOOST_CHECK(!result.extended);
    BOOST_CHECK(!result.expired);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(now_equal_until_without_want_extend_is_expired)
{
    std::string err = "prior";
    modelnet::SwarmNotCohort note;
    note.cohort_id = "cohort-a";
    note.now_ms = 20;
    note.until_ms = 20;
    note.want_extend = false;
    const modelnet::SwarmNotCohortResult result = modelnet::SwarmNoteNotCohort(note, err);
    BOOST_CHECK(!result.extended);
    BOOST_CHECK(result.expired);
    BOOST_CHECK_EQUAL(result.code, "EXPIRED");
    BOOST_CHECK_EQUAL(err, "EXPIRED");
}

BOOST_AUTO_TEST_CASE(now_before_until_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotCohort note;
    note.cohort_id = "cohort-a";
    note.now_ms = 19;
    note.until_ms = 20;
    note.want_extend = false;
    const modelnet::SwarmNotCohortResult result = modelnet::SwarmNoteNotCohort(note, err);
    BOOST_CHECK(!result.extended);
    BOOST_CHECK(!result.expired);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
