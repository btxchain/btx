// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notstale.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notstale_tests, BasicTestingSetup)

static modelnet::SwarmNotStale NotedNote()
{
    modelnet::SwarmNotStale note;
    note.epoch_id = "epoch-1";
    note.want_commit = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_epoch_id_is_epoch)
{
    modelnet::SwarmNotStale note = NotedNote();
    note.epoch_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotStaleResult result = modelnet::SwarmNoteNotStale(note, err);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK_EQUAL(result.code, "EPOCH");
    BOOST_CHECK_EQUAL(err, "EPOCH");
}

BOOST_AUTO_TEST_CASE(want_commit_is_stale)
{
    modelnet::SwarmNotStale note = NotedNote();
    note.want_commit = true;
    std::string err = "prior";
    const modelnet::SwarmNotStaleResult result = modelnet::SwarmNoteNotStale(note, err);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK_EQUAL(result.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotStale note = NotedNote();
    note.want_commit = false;
    std::string err = "prior";
    const modelnet::SwarmNotStaleResult result = modelnet::SwarmNoteNotStale(note, err);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
