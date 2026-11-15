// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocohortinc2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocohortinc2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_cohort_id_is_cohort)
{
    modelnet::SwarmNotNoCohortInc2 note;
    note.inclusive = true;
    note.want_exclude = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCohortInc2Result result = modelnet::SwarmNoteNotNoCohortInc2(note, err);
    BOOST_CHECK(!result.excluded);
    BOOST_CHECK_EQUAL(result.code, "COHORT");
    BOOST_CHECK_EQUAL(err, "COHORT");
}

BOOST_AUTO_TEST_CASE(inclusive_is_stays_when_want_exclude_is_false)
{
    modelnet::SwarmNotNoCohortInc2 note;
    note.cohort_id = "cohort-1";
    note.inclusive = true;
    note.want_exclude = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCohortInc2Result result = modelnet::SwarmNoteNotNoCohortInc2(note, err);
    BOOST_CHECK(!result.excluded);
    BOOST_CHECK_EQUAL(result.code, "STAYS");
    BOOST_CHECK_EQUAL(err, "STAYS");
}

BOOST_AUTO_TEST_CASE(want_exclude_is_held)
{
    modelnet::SwarmNotNoCohortInc2 note;
    note.cohort_id = "cohort-1";
    note.inclusive = false;
    note.want_exclude = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCohortInc2Result result = modelnet::SwarmNoteNotNoCohortInc2(note, err);
    BOOST_CHECK(!result.excluded);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCohortInc2 note;
    note.cohort_id = "cohort-1";
    note.inclusive = false;
    note.want_exclude = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCohortInc2Result result = modelnet::SwarmNoteNotNoCohortInc2(note, err);
    BOOST_CHECK(!result.excluded);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
