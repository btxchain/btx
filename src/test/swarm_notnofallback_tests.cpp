// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofallback.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofallback_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    std::string err = "prior";
    modelnet::SwarmNotNoFallback note;
    note.fallback = true;
    note.want_connect = true;
    const modelnet::SwarmNotNoFallbackResult result = modelnet::SwarmNoteNotNoFallback(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(fallback_without_want_connect_is_not_connected)
{
    std::string err = "prior";
    modelnet::SwarmNotNoFallback note;
    note.peer_id = "peer-chosen";
    note.fallback = true;
    note.want_connect = false;
    const modelnet::SwarmNotNoFallbackResult result = modelnet::SwarmNoteNotNoFallback(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_CONNECTED");
    BOOST_CHECK_EQUAL(err, "NOT_CONNECTED");
}

BOOST_AUTO_TEST_CASE(want_connect_on_a_chosen_peer_is_not_connected)
{
    std::string err = "prior";
    modelnet::SwarmNotNoFallback note;
    note.peer_id = "peer-chosen";
    note.fallback = false;
    note.want_connect = true;
    const modelnet::SwarmNotNoFallbackResult result = modelnet::SwarmNoteNotNoFallback(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_CONNECTED");
    BOOST_CHECK_EQUAL(err, "NOT_CONNECTED");
}

BOOST_AUTO_TEST_CASE(plain_chosen_peer_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoFallback note;
    note.peer_id = "peer-chosen";
    note.fallback = false;
    note.want_connect = false;
    const modelnet::SwarmNotNoFallbackResult result = modelnet::SwarmNoteNotNoFallback(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
