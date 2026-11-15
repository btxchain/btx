// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoevalself2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoevalself2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_report_id_is_report)
{
    modelnet::SwarmNotNoEvalSelf2 note;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalSelf2Result result = modelnet::SwarmNoteNotNoEvalSelf2(note, err);
    BOOST_CHECK_EQUAL(result.scored, false);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(same_author_is_not_scored)
{
    modelnet::SwarmNotNoEvalSelf2 note;
    note.report_id = "report-1";
    note.same_author = true;
    note.want_score = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalSelf2Result result = modelnet::SwarmNoteNotNoEvalSelf2(note, err);
    BOOST_CHECK_EQUAL(result.scored, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_SCORED");
    BOOST_CHECK_EQUAL(err, "NOT_SCORED");
}

BOOST_AUTO_TEST_CASE(want_score_is_held)
{
    modelnet::SwarmNotNoEvalSelf2 note;
    note.report_id = "report-1";
    note.same_author = false;
    note.want_score = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalSelf2Result result = modelnet::SwarmNoteNotNoEvalSelf2(note, err);
    BOOST_CHECK_EQUAL(result.scored, false);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoEvalSelf2 note;
    note.report_id = "report-1";
    note.same_author = false;
    note.want_score = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalSelf2Result result = modelnet::SwarmNoteNotNoEvalSelf2(note, err);
    BOOST_CHECK_EQUAL(result.scored, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
