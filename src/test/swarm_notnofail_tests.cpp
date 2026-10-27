// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofail.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofail_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    modelnet::SwarmNotNoFail note;
    std::string err = "prior";
    const modelnet::SwarmNotNoFailResult result = modelnet::SwarmNoteNotNoFail(note, err);
    BOOST_CHECK_EQUAL(result.connected, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(want_connect_is_not_connected)
{
    modelnet::SwarmNotNoFail note;
    note.peer_id = "peer-1";
    note.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFailResult result = modelnet::SwarmNoteNotNoFail(note, err);
    BOOST_CHECK_EQUAL(result.connected, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_CONNECTED");
    BOOST_CHECK_EQUAL(err, "NOT_CONNECTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoFail note;
    note.peer_id = "peer-1";
    note.want_connect = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFailResult result = modelnet::SwarmNoteNotNoFail(note, err);
    BOOST_CHECK_EQUAL(result.connected, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
