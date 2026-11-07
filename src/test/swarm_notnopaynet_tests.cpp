// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopaynet.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopaynet_tests, BasicTestingSetup)

static modelnet::SwarmNotNoPaynet NotedNote()
{
    modelnet::SwarmNotNoPaynet note;
    note.ledger_id = "ledger-1";
    note.want_broadcast = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_ledger_id_is_ledger)
{
    modelnet::SwarmNotNoPaynet note = NotedNote();
    note.ledger_id.clear();
    note.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPaynetResult result = modelnet::SwarmNoteNotNoPaynet(note, err);
    BOOST_CHECK_EQUAL(result.code, "LEDGER");
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "LEDGER");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_not_broadcast)
{
    modelnet::SwarmNotNoPaynet note = NotedNote();
    note.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPaynetResult result = modelnet::SwarmNoteNotNoPaynet(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_BROADCAST");
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "NOT_BROADCAST");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoPaynet note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoPaynetResult result = modelnet::SwarmNoteNotNoPaynet(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
