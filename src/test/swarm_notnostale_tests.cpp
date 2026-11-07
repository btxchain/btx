// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnostale.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnostale_tests, BasicTestingSetup)

static modelnet::SwarmNotNoStale NotedNote()
{
    modelnet::SwarmNotNoStale note;
    note.leader_id = "leader-1";
    note.stale = false;
    note.want_commit = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_leader_id_is_leader)
{
    modelnet::SwarmNotNoStale note = NotedNote();
    note.leader_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoStaleResult result = modelnet::SwarmNoteNotNoStale(note, err);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "LEADER");
    BOOST_CHECK_EQUAL(err, "LEADER");
}

BOOST_AUTO_TEST_CASE(stale_leader_is_stale)
{
    modelnet::SwarmNotNoStale note = NotedNote();
    note.stale = true;
    note.want_commit = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoStaleResult result = modelnet::SwarmNoteNotNoStale(note, err);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");
}

BOOST_AUTO_TEST_CASE(want_commit_while_fresh_is_stale)
{
    modelnet::SwarmNotNoStale note = NotedNote();
    note.stale = false;
    note.want_commit = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoStaleResult result = modelnet::SwarmNoteNotNoStale(note, err);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");
}

BOOST_AUTO_TEST_CASE(fresh_plain_note_is_noted)
{
    modelnet::SwarmNotNoStale note = NotedNote();
    note.stale = false;
    note.want_commit = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoStaleResult result = modelnet::SwarmNoteNotNoStale(note, err);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
