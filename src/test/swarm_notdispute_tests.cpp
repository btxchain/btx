// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdispute.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notdispute_tests, BasicTestingSetup)

static modelnet::SwarmNotDispute NotedNote()
{
    modelnet::SwarmNotDispute note;
    note.receipt_id = "receipt-1";
    note.want_settle = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_receipt_id_is_receipt)
{
    modelnet::SwarmNotDispute note = NotedNote();
    note.receipt_id.clear();
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotDisputeResult result = modelnet::SwarmNoteNotDispute(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "RECEIPT");
    BOOST_CHECK_EQUAL(err, "RECEIPT");
}

BOOST_AUTO_TEST_CASE(want_settle_is_not_settled)
{
    modelnet::SwarmNotDispute note = NotedNote();
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotDisputeResult result = modelnet::SwarmNoteNotDispute(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOT_SETTLED");
    BOOST_CHECK_EQUAL(err, "NOT_SETTLED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotDispute note = NotedNote();
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotDisputeResult result = modelnet::SwarmNoteNotDispute(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
