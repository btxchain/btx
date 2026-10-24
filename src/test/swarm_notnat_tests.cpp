// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnat.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnat_tests, BasicTestingSetup)

static modelnet::SwarmNotNat NotedNote()
{
    modelnet::SwarmNotNat note;
    note.peer_id = "peer-1";
    note.want_traverse = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    modelnet::SwarmNotNat note = NotedNote();
    note.peer_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNatResult result = modelnet::SwarmNoteNotNat(note, err);
    BOOST_CHECK(!result.traversed);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(want_traverse_is_no_nat)
{
    modelnet::SwarmNotNat note = NotedNote();
    note.want_traverse = true;
    std::string err = "prior";
    const modelnet::SwarmNotNatResult result = modelnet::SwarmNoteNotNat(note, err);
    BOOST_CHECK(!result.traversed);
    BOOST_CHECK_EQUAL(result.code, "NO_NAT");
    BOOST_CHECK_EQUAL(err, "NO_NAT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNat note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNatResult result = modelnet::SwarmNoteNotNat(note, err);
    BOOST_CHECK(!result.traversed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
