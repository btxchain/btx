// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_authorsign.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_authorsign_tests, BasicTestingSetup)

static modelnet::SwarmAuthorSign NotedSign()
{
    modelnet::SwarmAuthorSign note;
    note.report_id = "report-1";
    note.author_id = "author-1";
    note.signer_id = "signer-1";
    note.want_sign = false;
    return note;
}

static void ExpectUnsigned(const modelnet::SwarmAuthorSignResult& result)
{
    BOOST_CHECK(!result.signed_report);
}

BOOST_AUTO_TEST_CASE(empty_report_id_is_report)
{
    modelnet::SwarmAuthorSign note = NotedSign();
    note.report_id.clear();
    std::string err = "prior";
    const modelnet::SwarmAuthorSignResult result = modelnet::SwarmNoteAuthorSign(note, err);
    ExpectUnsigned(result);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(empty_author_id_is_report)
{
    modelnet::SwarmAuthorSign note = NotedSign();
    note.author_id.clear();
    std::string err = "prior";
    const modelnet::SwarmAuthorSignResult result = modelnet::SwarmNoteAuthorSign(note, err);
    ExpectUnsigned(result);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(empty_signer_id_is_report)
{
    modelnet::SwarmAuthorSign note = NotedSign();
    note.signer_id.clear();
    std::string err = "prior";
    const modelnet::SwarmAuthorSignResult result = modelnet::SwarmNoteAuthorSign(note, err);
    ExpectUnsigned(result);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(empty_report_id_wins_over_self_and_want_sign)
{
    modelnet::SwarmAuthorSign note = NotedSign();
    note.report_id.clear();
    note.author_id = "same-1";
    note.signer_id = "same-1";
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmAuthorSignResult result = modelnet::SwarmNoteAuthorSign(note, err);
    ExpectUnsigned(result);
    BOOST_CHECK_EQUAL(result.code, "REPORT");
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(same_author_and_signer_with_want_sign_is_self)
{
    modelnet::SwarmAuthorSign note = NotedSign();
    note.author_id = "same-1";
    note.signer_id = "same-1";
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmAuthorSignResult result = modelnet::SwarmNoteAuthorSign(note, err);
    ExpectUnsigned(result);
    BOOST_CHECK_EQUAL(result.code, "SELF");
    BOOST_CHECK_EQUAL(err, "SELF");
}

BOOST_AUTO_TEST_CASE(want_sign_with_different_ids_is_held)
{
    modelnet::SwarmAuthorSign note = NotedSign();
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmAuthorSignResult result = modelnet::SwarmNoteAuthorSign(note, err);
    ExpectUnsigned(result);
    BOOST_CHECK_NE(note.author_id, note.signer_id);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(different_ids_without_want_sign_is_noted)
{
    modelnet::SwarmAuthorSign note = NotedSign();
    std::string err = "prior";
    const modelnet::SwarmAuthorSignResult result = modelnet::SwarmNoteAuthorSign(note, err);
    ExpectUnsigned(result);
    BOOST_CHECK_NE(note.author_id, note.signer_id);
    BOOST_CHECK(!note.want_sign);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
