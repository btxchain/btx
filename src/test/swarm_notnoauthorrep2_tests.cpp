// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoauthorrep2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoauthorrep2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_report_id)
{
    modelnet::SwarmNotNoAuthorRep2 note;
    note.report_id.clear();
    note.same_author = true;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthorRep2Result result = modelnet::SwarmNoteNotNoAuthorRep2(note, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(same_author_not_signed)
{
    modelnet::SwarmNotNoAuthorRep2 note;
    note.report_id = "report-1";
    note.same_author = true;
    note.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthorRep2Result result = modelnet::SwarmNoteNotNoAuthorRep2(note, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
}

BOOST_AUTO_TEST_CASE(want_sign)
{
    modelnet::SwarmNotNoAuthorRep2 note;
    note.report_id = "report-1";
    note.same_author = false;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthorRep2Result result = modelnet::SwarmNoteNotNoAuthorRep2(note, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoAuthorRep2 note;
    BOOST_CHECK(!note.same_author);
    BOOST_CHECK(!note.want_sign);
    note.report_id = "report-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoAuthorRep2Result result = modelnet::SwarmNoteNotNoAuthorRep2(note, err);
    BOOST_CHECK(!result.signed_ok);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
