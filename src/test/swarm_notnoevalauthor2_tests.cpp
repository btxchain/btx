// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoevalauthor2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoevalauthor2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_report_id)
{
    modelnet::SwarmNotNoEvalAuthor2 note;
    note.report_id.clear();
    note.self_author = true;
    note.want_score = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalAuthor2Result result = modelnet::SwarmNoteNotNoEvalAuthor2(note, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(self_author_not_scored)
{
    modelnet::SwarmNotNoEvalAuthor2 note;
    note.report_id = "report-1";
    note.self_author = true;
    note.want_score = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalAuthor2Result result = modelnet::SwarmNoteNotNoEvalAuthor2(note, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "NOT_SCORED");
    BOOST_CHECK_EQUAL(err, "NOT_SCORED");
}

BOOST_AUTO_TEST_CASE(want_score_is_held)
{
    modelnet::SwarmNotNoEvalAuthor2 note;
    note.report_id = "report-1";
    note.self_author = false;
    note.want_score = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalAuthor2Result result = modelnet::SwarmNoteNotNoEvalAuthor2(note, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoEvalAuthor2 note;
    BOOST_CHECK(!note.self_author);
    BOOST_CHECK(!note.want_score);
    note.report_id = "report-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalAuthor2Result result = modelnet::SwarmNoteNotNoEvalAuthor2(note, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
