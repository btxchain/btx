// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofalsecompat.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofalsecompat_tests, BasicTestingSetup)

static modelnet::SwarmNotNoFalseCompat NotedNote()
{
    modelnet::SwarmNotNoFalseCompat note;
    note.page_id = "page-1";
    note.false_compat = false;
    note.want_share = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_page_id_is_page)
{
    modelnet::SwarmNotNoFalseCompat note = NotedNote();
    note.page_id.clear();
    note.false_compat = true;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFalseCompatResult result = modelnet::SwarmNoteNotNoFalseCompat(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(false_compat_without_want_share_is_family_not_compat)
{
    modelnet::SwarmNotNoFalseCompat note = NotedNote();
    note.false_compat = true;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFalseCompatResult result = modelnet::SwarmNoteNotNoFalseCompat(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "FAMILY_NOT_COMPAT");
    BOOST_CHECK_EQUAL(err, "FAMILY_NOT_COMPAT");
}

BOOST_AUTO_TEST_CASE(want_share_is_not_shared)
{
    modelnet::SwarmNotNoFalseCompat note = NotedNote();
    note.false_compat = false;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFalseCompatResult result = modelnet::SwarmNoteNotNoFalseCompat(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_SHARED");
    BOOST_CHECK_EQUAL(err, "NOT_SHARED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoFalseCompat note = NotedNote();
    note.false_compat = false;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFalseCompatResult result = modelnet::SwarmNoteNotNoFalseCompat(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
