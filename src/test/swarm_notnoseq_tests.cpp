// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoseq.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoseq_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_batch_id_is_batch)
{
    modelnet::SwarmNotNoSeq note;
    note.batch_id.clear();
    note.want_step = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSeqResult result = modelnet::SwarmNoteNotNoSeq(note, err);
    BOOST_CHECK(!result.stepped);
    BOOST_CHECK_EQUAL(result.l1_txs, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "BATCH");
    BOOST_CHECK_EQUAL(err, "BATCH");
}

BOOST_AUTO_TEST_CASE(want_step_is_one_step)
{
    modelnet::SwarmNotNoSeq note;
    note.batch_id = "batch-1";
    note.want_step = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSeqResult result = modelnet::SwarmNoteNotNoSeq(note, err);
    BOOST_CHECK(!result.stepped);
    BOOST_CHECK_EQUAL(result.l1_txs, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "ONE_STEP");
    BOOST_CHECK_EQUAL(err, "ONE_STEP");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSeq note;
    note.batch_id = "batch-1";
    note.want_step = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSeqResult result = modelnet::SwarmNoteNotNoSeq(note, err);
    BOOST_CHECK(!result.stepped);
    BOOST_CHECK_EQUAL(result.l1_txs, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
