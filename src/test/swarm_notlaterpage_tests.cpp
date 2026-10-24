// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notlaterpage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notlaterpage_tests, BasicTestingSetup)

static modelnet::SwarmNotLaterPage NotedNote()
{
    modelnet::SwarmNotLaterPage note;
    note.page_id = "page-1";
    note.revoked = false;
    note.want_read = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_page_id_is_page)
{
    modelnet::SwarmNotLaterPage note = NotedNote();
    note.page_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotLaterPageResult result = modelnet::SwarmNoteNotLaterPage(note, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(revoked_without_want_read_is_revoked)
{
    modelnet::SwarmNotLaterPage note = NotedNote();
    note.revoked = true;
    note.want_read = false;
    std::string err = "prior";
    const modelnet::SwarmNotLaterPageResult result = modelnet::SwarmNoteNotLaterPage(note, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "REVOKED");
    BOOST_CHECK_EQUAL(err, "REVOKED");
}

BOOST_AUTO_TEST_CASE(want_read_without_revoked_is_revoked)
{
    modelnet::SwarmNotLaterPage note = NotedNote();
    note.revoked = false;
    note.want_read = true;
    std::string err = "prior";
    const modelnet::SwarmNotLaterPageResult result = modelnet::SwarmNoteNotLaterPage(note, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "REVOKED");
    BOOST_CHECK_EQUAL(err, "REVOKED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotLaterPage note = NotedNote();
    note.revoked = false;
    note.want_read = false;
    std::string err = "prior";
    const modelnet::SwarmNotLaterPageResult result = modelnet::SwarmNoteNotLaterPage(note, err);
    BOOST_CHECK(!result.read);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
