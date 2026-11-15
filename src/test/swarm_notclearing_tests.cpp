// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notclearing.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notclearing_tests, BasicTestingSetup)

static modelnet::SwarmNotClearing NotedNote()
{
    modelnet::SwarmNotClearing note;
    note.batch_id = "batch-1";
    note.want_settle = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_batch_id_is_batch)
{
    modelnet::SwarmNotClearing note = NotedNote();
    note.batch_id.clear();
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotClearingResult result = modelnet::SwarmNoteNotClearing(note, err);
    BOOST_CHECK_EQUAL(result.code, "BATCH");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK_EQUAL(err, "BATCH");
}

BOOST_AUTO_TEST_CASE(want_settle_is_not_settled)
{
    modelnet::SwarmNotClearing note = NotedNote();
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotClearingResult result = modelnet::SwarmNoteNotClearing(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_SETTLED");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK_EQUAL(err, "NOT_SETTLED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotClearing note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotClearingResult result = modelnet::SwarmNoteNotClearing(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
