// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nottxid.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nottxid_tests, BasicTestingSetup)

static modelnet::SwarmNotTxid NotedNote()
{
    modelnet::SwarmNotTxid note;
    note.payment_id = "payment-1";
    note.want_store = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_payment_id_is_payment)
{
    modelnet::SwarmNotTxid note = NotedNote();
    note.payment_id.clear();
    note.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmNotTxidResult result = modelnet::SwarmNoteNotTxid(note, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "PAYMENT");
    BOOST_CHECK_EQUAL(err, "PAYMENT");
}

BOOST_AUTO_TEST_CASE(want_store_is_not_stored)
{
    modelnet::SwarmNotTxid note = NotedNote();
    note.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmNotTxidResult result = modelnet::SwarmNoteNotTxid(note, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOT_STORED");
    BOOST_CHECK_EQUAL(err, "NOT_STORED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotTxid note = NotedNote();
    note.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmNotTxidResult result = modelnet::SwarmNoteNotTxid(note, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
