// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoevalself.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoevalself_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_report_id)
{
    modelnet::SwarmNotNoEvalSelf note;
    note.report_id.clear();
    note.author = true;
    note.want_score = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalSelfResult result = modelnet::SwarmNoteNotNoEvalSelf(note, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(author_is_self)
{
    modelnet::SwarmNotNoEvalSelf note;
    note.report_id = "report-1";
    note.author = true;
    note.want_score = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalSelfResult result = modelnet::SwarmNoteNotNoEvalSelf(note, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "SELF");
    BOOST_CHECK_EQUAL(err, "SELF");
}

BOOST_AUTO_TEST_CASE(want_score_is_held)
{
    modelnet::SwarmNotNoEvalSelf note;
    note.report_id = "report-1";
    note.author = false;
    note.want_score = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalSelfResult result = modelnet::SwarmNoteNotNoEvalSelf(note, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoEvalSelf note;
    BOOST_CHECK(!note.author);
    BOOST_CHECK(!note.want_score);
    note.report_id = "report-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoEvalSelfResult result = modelnet::SwarmNoteNotNoEvalSelf(note, err);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
