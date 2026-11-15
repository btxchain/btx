// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodedup.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnodedup_tests, BasicTestingSetup)

static modelnet::SwarmNotNoDedup NotedNote()
{
    modelnet::SwarmNotNoDedup note;
    note.piece_id = "piece-1";
    note.other_realm = false;
    note.want_dedup = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_piece_id_is_piece)
{
    modelnet::SwarmNotNoDedup note = NotedNote();
    note.piece_id.clear();
    note.other_realm = true;
    note.want_dedup = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDedupResult result = modelnet::SwarmNoteNotNoDedup(note, err);
    BOOST_CHECK(!result.deduped);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(other_realm_is_dedup_private)
{
    modelnet::SwarmNotNoDedup note = NotedNote();
    note.other_realm = true;
    note.want_dedup = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDedupResult result = modelnet::SwarmNoteNotNoDedup(note, err);
    BOOST_CHECK(!result.deduped);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "DEDUP_PRIVATE");
    BOOST_CHECK_EQUAL(err, "DEDUP_PRIVATE");
}

BOOST_AUTO_TEST_CASE(want_dedup_is_held)
{
    modelnet::SwarmNotNoDedup note = NotedNote();
    note.other_realm = false;
    note.want_dedup = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDedupResult result = modelnet::SwarmNoteNotNoDedup(note, err);
    BOOST_CHECK(!result.deduped);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoDedup note = NotedNote();
    note.other_realm = false;
    note.want_dedup = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDedupResult result = modelnet::SwarmNoteNotNoDedup(note, err);
    BOOST_CHECK(!result.deduped);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
