// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoauthor2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoauthor2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_report_id)
{
    modelnet::SwarmNotNoAuthor2 note;
    note.report_id.clear();
    note.author = true;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthor2Result result = modelnet::SwarmNoteNotNoAuthor2(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(author_not_signer)
{
    modelnet::SwarmNotNoAuthor2 note;
    note.report_id = "report-1";
    note.author = true;
    note.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthor2Result result = modelnet::SwarmNoteNotNoAuthor2(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOT_SIGNER");
    BOOST_CHECK_EQUAL(err, "NOT_SIGNER");
}

BOOST_AUTO_TEST_CASE(want_sign)
{
    modelnet::SwarmNotNoAuthor2 note;
    note.report_id = "report-1";
    note.author = false;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthor2Result result = modelnet::SwarmNoteNotNoAuthor2(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoAuthor2 note;
    BOOST_CHECK(!note.author);
    BOOST_CHECK(!note.want_sign);
    note.report_id = "report-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthor2Result result = modelnet::SwarmNoteNotNoAuthor2(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
