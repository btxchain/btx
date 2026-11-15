// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoroute.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoroute_tests, BasicTestingSetup)

static modelnet::SwarmNotNoRoute NotedNote()
{
    modelnet::SwarmNotNoRoute note;
    note.peer_id = "peer-1";
    note.want_reach = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    modelnet::SwarmNotNoRoute note = NotedNote();
    note.peer_id.clear();
    note.want_reach = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRouteResult result = modelnet::SwarmNoteNotNoRoute(note, err);
    BOOST_CHECK(!result.reached);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(want_reach_is_unqualified)
{
    modelnet::SwarmNotNoRoute note = NotedNote();
    note.want_reach = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRouteResult result = modelnet::SwarmNoteNotNoRoute(note, err);
    BOOST_CHECK(!result.reached);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoRoute note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoRouteResult result = modelnet::SwarmNoteNotNoRoute(note, err);
    BOOST_CHECK(!result.reached);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
