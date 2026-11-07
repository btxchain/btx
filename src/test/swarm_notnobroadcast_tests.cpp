// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobroadcast.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnobroadcast_tests, BasicTestingSetup)

static modelnet::SwarmNotNoBroadcast NotedNote()
{
    modelnet::SwarmNotNoBroadcast note;
    note.chain_id = "chain-1";
    note.mainnet = false;
    note.want_broadcast = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_chain_id_is_chain)
{
    modelnet::SwarmNotNoBroadcast note = NotedNote();
    note.chain_id.clear();
    note.mainnet = true;
    note.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoBroadcastResult result = modelnet::SwarmNoteNotNoBroadcast(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK_EQUAL(result.code, "CHAIN");
    BOOST_CHECK_EQUAL(err, "CHAIN");
}

BOOST_AUTO_TEST_CASE(mainnet_is_not_broadcast)
{
    modelnet::SwarmNotNoBroadcast note = NotedNote();
    note.mainnet = true;
    note.want_broadcast = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoBroadcastResult result = modelnet::SwarmNoteNotNoBroadcast(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_BROADCAST");
    BOOST_CHECK_EQUAL(err, "NOT_BROADCAST");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_held)
{
    modelnet::SwarmNotNoBroadcast note = NotedNote();
    note.mainnet = false;
    note.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoBroadcastResult result = modelnet::SwarmNoteNotNoBroadcast(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoBroadcast note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoBroadcastResult result = modelnet::SwarmNoteNotNoBroadcast(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
