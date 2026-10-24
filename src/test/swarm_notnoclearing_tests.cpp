// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclearing.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoclearing_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_batch_id_is_batch)
{
    std::string err = "prior";
    modelnet::SwarmNotNoClearing note;
    note.want_pay = true;
    const modelnet::SwarmNotNoClearingResult result = modelnet::SwarmNoteNotNoClearing(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.l1_txs, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "BATCH");
    BOOST_CHECK_EQUAL(err, "BATCH");
}

BOOST_AUTO_TEST_CASE(want_pay_is_netted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoClearing note;
    note.batch_id = "batch-1";
    note.want_pay = true;
    const modelnet::SwarmNotNoClearingResult result = modelnet::SwarmNoteNotNoClearing(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.l1_txs, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "NETTED");
    BOOST_CHECK_EQUAL(err, "NETTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoClearing note;
    note.batch_id = "batch-1";
    note.want_pay = false;
    const modelnet::SwarmNotNoClearingResult result = modelnet::SwarmNoteNotNoClearing(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.l1_txs, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
