// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoauthor.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoauthor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_report_id)
{
    modelnet::SwarmNotNoAuthor note;
    note.report_id.clear();
    note.self_signed = true;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthorResult result = modelnet::SwarmNoteNotNoAuthor(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(self_signed)
{
    modelnet::SwarmNotNoAuthor note;
    note.report_id = "report-1";
    note.self_signed = true;
    note.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthorResult result = modelnet::SwarmNoteNotNoAuthor(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "SAME_EVALUATOR");
    BOOST_CHECK_EQUAL(err, "SAME_EVALUATOR");
}

BOOST_AUTO_TEST_CASE(want_sign)
{
    modelnet::SwarmNotNoAuthor note;
    note.report_id = "report-1";
    note.self_signed = false;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthorResult result = modelnet::SwarmNoteNotNoAuthor(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "NOT_ACCEPTED");
    BOOST_CHECK_EQUAL(err, "NOT_ACCEPTED");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoAuthor note;
    BOOST_CHECK(!note.self_signed);
    BOOST_CHECK(!note.want_sign);
    note.report_id = "report-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthorResult result = modelnet::SwarmNoteNotNoAuthor(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
