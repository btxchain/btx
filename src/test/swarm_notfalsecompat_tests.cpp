// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfalsecompat.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notfalsecompat_tests, BasicTestingSetup)

static modelnet::SwarmNotFalseCompat NotedNote()
{
    modelnet::SwarmNotFalseCompat note;
    note.peer_id = "peer-1";
    note.want_share = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    modelnet::SwarmNotFalseCompat note = NotedNote();
    note.peer_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotFalseCompatResult result = modelnet::SwarmNoteNotFalseCompat(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(want_share_is_not_live)
{
    modelnet::SwarmNotFalseCompat note = NotedNote();
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotFalseCompatResult result = modelnet::SwarmNoteNotFalseCompat(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_LIVE");
    BOOST_CHECK_EQUAL(err, "NOT_LIVE");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotFalseCompat note = NotedNote();
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotFalseCompatResult result = modelnet::SwarmNoteNotFalseCompat(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
