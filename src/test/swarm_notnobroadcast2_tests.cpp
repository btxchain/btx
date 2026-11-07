// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobroadcast2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnobroadcast2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_tx_id_is_tx)
{
    modelnet::SwarmNotNoBroadcast2 note;
    note.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoBroadcast2Result result = modelnet::SwarmNoteNotNoBroadcast2(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "TX");
    BOOST_CHECK_EQUAL(err, "TX");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_held)
{
    modelnet::SwarmNotNoBroadcast2 note;
    note.tx_id = "tx-1";
    note.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoBroadcast2Result result = modelnet::SwarmNoteNotNoBroadcast2(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoBroadcast2 note;
    note.tx_id = "tx-1";
    note.want_broadcast = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoBroadcast2Result result = modelnet::SwarmNoteNotNoBroadcast2(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
