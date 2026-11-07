// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfees.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notfees_tests, BasicTestingSetup)

static modelnet::SwarmNotFees NotedNote()
{
    modelnet::SwarmNotFees note;
    note.invoice_id = "invoice-1";
    note.want_publish = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_invoice_id_is_invoice)
{
    modelnet::SwarmNotFees note = NotedNote();
    note.invoice_id.clear();
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotFeesResult result = modelnet::SwarmNoteNotFees(note, err);
    BOOST_CHECK_EQUAL(result.code, "INVOICE");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK_EQUAL(result.latency_us, 0);
    BOOST_CHECK_EQUAL(err, "INVOICE");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    modelnet::SwarmNotFees note = NotedNote();
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotFeesResult result = modelnet::SwarmNoteNotFees(note, err);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK_EQUAL(result.latency_us, 0);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotFees note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotFeesResult result = modelnet::SwarmNoteNotFees(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK_EQUAL(result.latency_us, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
