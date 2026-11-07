// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnooneclose.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnooneclose_tests, BasicTestingSetup)

static modelnet::SwarmNotNoOneClose NotedNote()
{
    modelnet::SwarmNotNoOneClose note;
    note.batch_id = "batch-1";
    note.want_close_many = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_batch_id_is_batch)
{
    modelnet::SwarmNotNoOneClose note = NotedNote();
    note.batch_id.clear();
    note.want_close_many = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoOneCloseResult result = modelnet::SwarmNoteNotNoOneClose(note, err);
    BOOST_CHECK_EQUAL(result.code, "BATCH");
    BOOST_CHECK(!result.closed);
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK_EQUAL(err, "BATCH");
}

BOOST_AUTO_TEST_CASE(want_close_many_is_one_close)
{
    modelnet::SwarmNotNoOneClose note = NotedNote();
    note.want_close_many = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoOneCloseResult result = modelnet::SwarmNoteNotNoOneClose(note, err);
    BOOST_CHECK_EQUAL(result.code, "ONE_CLOSE");
    BOOST_CHECK(!result.closed);
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK_EQUAL(err, "ONE_CLOSE");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoOneClose note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoOneCloseResult result = modelnet::SwarmNoteNotNoOneClose(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.closed);
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
