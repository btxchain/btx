// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocohort.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocohort_tests, BasicTestingSetup)

static modelnet::SwarmNotNoCohort NotedNote()
{
    modelnet::SwarmNotNoCohort note;
    note.cohort_id = "cohort-1";
    note.now_ms = 10;
    note.until_ms = 20;
    note.want_spend = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_cohort_id_is_cohort)
{
    modelnet::SwarmNotNoCohort note = NotedNote();
    note.cohort_id.clear();
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCohortResult result = modelnet::SwarmNoteNotNoCohort(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "COHORT");
    BOOST_CHECK_EQUAL(err, "COHORT");
}

BOOST_AUTO_TEST_CASE(now_equal_until_is_expired)
{
    modelnet::SwarmNotNoCohort note = NotedNote();
    note.now_ms = 20;
    note.until_ms = 20;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCohortResult result = modelnet::SwarmNoteNotNoCohort(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "EXPIRED");
    BOOST_CHECK_EQUAL(err, "EXPIRED");
}

BOOST_AUTO_TEST_CASE(want_spend_inside_window_is_held)
{
    modelnet::SwarmNotNoCohort note = NotedNote();
    note.now_ms = 10;
    note.until_ms = 20;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCohortResult result = modelnet::SwarmNoteNotNoCohort(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(inside_window_is_noted)
{
    modelnet::SwarmNotNoCohort note = NotedNote();
    note.now_ms = 10;
    note.until_ms = 20;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCohortResult result = modelnet::SwarmNoteNotNoCohort(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
