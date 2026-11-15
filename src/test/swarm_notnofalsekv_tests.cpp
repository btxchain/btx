// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofalsekv.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofalsekv_tests, BasicTestingSetup)

static modelnet::SwarmNotNoFalseKv NotedNote()
{
    modelnet::SwarmNotNoFalseKv note;
    note.page_id = "page-1";
    note.false_claim = false;
    note.want_share = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_page_id_is_page)
{
    modelnet::SwarmNotNoFalseKv note = NotedNote();
    note.page_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoFalseKvResult result = modelnet::SwarmNoteNotNoFalseKv(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(false_claim_without_want_share_is_not_shared)
{
    modelnet::SwarmNotNoFalseKv note = NotedNote();
    note.false_claim = true;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFalseKvResult result = modelnet::SwarmNoteNotNoFalseKv(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_SHARED");
    BOOST_CHECK_EQUAL(err, "NOT_SHARED");
}

BOOST_AUTO_TEST_CASE(want_share_without_false_claim_is_held)
{
    modelnet::SwarmNotNoFalseKv note = NotedNote();
    note.false_claim = false;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFalseKvResult result = modelnet::SwarmNoteNotNoFalseKv(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoFalseKv note = NotedNote();
    note.false_claim = false;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFalseKvResult result = modelnet::SwarmNoteNotNoFalseKv(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
