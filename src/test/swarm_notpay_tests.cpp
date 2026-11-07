// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notpay.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notpay_tests, BasicTestingSetup)

static modelnet::SwarmNotPay NotedNote()
{
    modelnet::SwarmNotPay note;
    note.invoice_id = "invoice-1";
    note.want_settle = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_invoice_id_is_invoice)
{
    modelnet::SwarmNotPay note = NotedNote();
    note.invoice_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotPayResult result = modelnet::SwarmNoteNotPay(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "INVOICE");
    BOOST_CHECK_EQUAL(err, "INVOICE");
}

BOOST_AUTO_TEST_CASE(want_settle_is_not_settled)
{
    modelnet::SwarmNotPay note = NotedNote();
    note.want_settle = true;
    std::string err = "prior";
    const modelnet::SwarmNotPayResult result = modelnet::SwarmNoteNotPay(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOT_SETTLED");
    BOOST_CHECK_EQUAL(err, "NOT_SETTLED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotPay note = NotedNote();
    note.want_settle = false;
    std::string err = "prior";
    const modelnet::SwarmNotPayResult result = modelnet::SwarmNoteNotPay(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
