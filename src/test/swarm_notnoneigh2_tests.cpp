// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoneigh2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoneigh2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNeigh2 note;
    note.outside_set = true;
    note.want_connect = true;
    const modelnet::SwarmNotNoNeigh2Result result = modelnet::SwarmNoteNotNoNeigh2(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(outside_set_is_not_connected)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNeigh2 note;
    note.peer_id = "peer-1";
    note.outside_set = true;
    note.want_connect = false;
    const modelnet::SwarmNotNoNeigh2Result result = modelnet::SwarmNoteNotNoNeigh2(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_CONNECTED");
    BOOST_CHECK_EQUAL(err, "NOT_CONNECTED");
}

BOOST_AUTO_TEST_CASE(want_connect_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNeigh2 note;
    note.peer_id = "peer-1";
    note.outside_set = false;
    note.want_connect = true;
    const modelnet::SwarmNotNoNeigh2Result result = modelnet::SwarmNoteNotNoNeigh2(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNeigh2 note;
    note.peer_id = "peer-1";
    note.outside_set = false;
    note.want_connect = false;
    const modelnet::SwarmNotNoNeigh2Result result = modelnet::SwarmNoteNotNoNeigh2(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
