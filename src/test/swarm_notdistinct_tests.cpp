// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdistinct.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notdistinct_tests, BasicTestingSetup)

static modelnet::SwarmNotDistinct NotedNote()
{
    modelnet::SwarmNotDistinct note;
    note.report_id = "report-1";
    note.same_author = false;
    note.want_sign = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_report_id_is_report)
{
    modelnet::SwarmNotDistinct note = NotedNote();
    note.report_id.clear();
    note.same_author = true;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotDistinctResult result = modelnet::SwarmNoteNotDistinct(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(same_author_is_same_evaluator)
{
    modelnet::SwarmNotDistinct note = NotedNote();
    note.same_author = true;
    note.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmNotDistinctResult result = modelnet::SwarmNoteNotDistinct(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "SAME_EVALUATOR");
    BOOST_CHECK_EQUAL(err, "SAME_EVALUATOR");
}

BOOST_AUTO_TEST_CASE(want_sign_is_not_accepted)
{
    modelnet::SwarmNotDistinct note = NotedNote();
    note.same_author = false;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotDistinctResult result = modelnet::SwarmNoteNotDistinct(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "NOT_ACCEPTED");
    BOOST_CHECK_EQUAL(err, "NOT_ACCEPTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotDistinct note = NotedNote();
    note.same_author = false;
    note.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmNotDistinctResult result = modelnet::SwarmNoteNotDistinct(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
