// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoauthor3.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoauthor3_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_report_id)
{
    modelnet::SwarmNotNoAuthor3 note;
    note.report_id.clear();
    note.self_sign = true;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthor3Result result = modelnet::SwarmNoteNotNoAuthor3(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(self_sign_not_signed)
{
    modelnet::SwarmNotNoAuthor3 note;
    note.report_id = "report-1";
    note.self_sign = true;
    note.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthor3Result result = modelnet::SwarmNoteNotNoAuthor3(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK_EQUAL(result.code, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
}

BOOST_AUTO_TEST_CASE(want_sign)
{
    modelnet::SwarmNotNoAuthor3 note;
    note.report_id = "report-1";
    note.self_sign = false;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthor3Result result = modelnet::SwarmNoteNotNoAuthor3(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoAuthor3 note;
    BOOST_CHECK(!note.self_sign);
    BOOST_CHECK(!note.want_sign);
    note.report_id = "report-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthor3Result result = modelnet::SwarmNoteNotNoAuthor3(note, err);
    BOOST_CHECK(!result.signed_report);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
