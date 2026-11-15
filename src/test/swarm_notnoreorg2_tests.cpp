// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoreorg2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoreorg2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoReorg2 NotedNote()
{
    modelnet::SwarmNotNoReorg2 note;
    note.tx_id = "tx-1";
    note.reorg = false;
    note.want_spend = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_tx_id_is_tx)
{
    modelnet::SwarmNotNoReorg2 note = NotedNote();
    note.tx_id.clear();
    note.reorg = true;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoReorg2Result result = modelnet::SwarmNoteNotNoReorg2(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "TX");
    BOOST_CHECK_EQUAL(err, "TX");
}

BOOST_AUTO_TEST_CASE(reorg_is_frozen)
{
    modelnet::SwarmNotNoReorg2 note = NotedNote();
    note.reorg = true;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoReorg2Result result = modelnet::SwarmNoteNotNoReorg2(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "FROZEN");
    BOOST_CHECK_EQUAL(err, "FROZEN");
}

BOOST_AUTO_TEST_CASE(want_spend_is_held)
{
    modelnet::SwarmNotNoReorg2 note = NotedNote();
    note.reorg = false;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoReorg2Result result = modelnet::SwarmNoteNotNoReorg2(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoReorg2 note = NotedNote();
    note.reorg = false;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoReorg2Result result = modelnet::SwarmNoteNotNoReorg2(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
