// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nota2a.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nota2a_tests, BasicTestingSetup)

static modelnet::SwarmNotA2a NotedNote()
{
    modelnet::SwarmNotA2a note;
    note.peer_id = "peer-1";
    note.want_connect = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    modelnet::SwarmNotA2a note = NotedNote();
    note.peer_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotA2aResult result = modelnet::SwarmNoteNotA2a(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(want_connect_is_not_connected)
{
    modelnet::SwarmNotA2a note = NotedNote();
    note.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmNotA2aResult result = modelnet::SwarmNoteNotA2a(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "NOT_CONNECTED");
    BOOST_CHECK_EQUAL(err, "NOT_CONNECTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotA2a note = NotedNote();
    note.want_connect = false;
    std::string err = "prior";
    const modelnet::SwarmNotA2aResult result = modelnet::SwarmNoteNotA2a(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
