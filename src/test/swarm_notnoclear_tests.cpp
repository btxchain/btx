// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclear.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoclear_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_batch_id_is_batch)
{
    modelnet::SwarmNotNoClear note;
    note.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoClearResult result = modelnet::SwarmNoteNotNoClear(note, err);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.l1_txs, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "BATCH");
    BOOST_CHECK_EQUAL(err, "BATCH");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_not_broadcast)
{
    modelnet::SwarmNotNoClear note;
    note.batch_id = "batch-1";
    note.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoClearResult result = modelnet::SwarmNoteNotNoClear(note, err);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.l1_txs, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "NOT_BROADCAST");
    BOOST_CHECK_EQUAL(err, "NOT_BROADCAST");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoClear note;
    note.batch_id = "batch-1";
    note.want_broadcast = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoClearResult result = modelnet::SwarmNoteNotNoClear(note, err);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.l1_txs, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
