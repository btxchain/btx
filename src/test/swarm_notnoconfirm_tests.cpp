// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoconfirm.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoconfirm_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_tx_id_is_tx)
{
    modelnet::SwarmNotNoConfirm note;
    note.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoConfirmResult result = modelnet::SwarmNoteNotNoConfirm(note, err);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.l1_txs, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "TX");
    BOOST_CHECK_EQUAL(err, "TX");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_confirmed_without_broadcast)
{
    modelnet::SwarmNotNoConfirm note;
    note.tx_id = "tx-1";
    note.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoConfirmResult result = modelnet::SwarmNoteNotNoConfirm(note, err);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.l1_txs, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "CONFIRMED_WITHOUT_BROADCAST");
    BOOST_CHECK_EQUAL(err, "CONFIRMED_WITHOUT_BROADCAST");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoConfirm note;
    note.tx_id = "tx-1";
    note.want_broadcast = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoConfirmResult result = modelnet::SwarmNoteNotNoConfirm(note, err);
    BOOST_CHECK_EQUAL(result.broadcast, false);
    BOOST_CHECK_EQUAL(result.l1_txs, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
