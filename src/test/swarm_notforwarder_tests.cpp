// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notforwarder.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notforwarder_tests, BasicTestingSetup)

static modelnet::SwarmNotForwarder NotedNote()
{
    modelnet::SwarmNotForwarder note;
    note.invoice_id = "invoice-1";
    note.want_charge = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_invoice_id_is_invoice)
{
    modelnet::SwarmNotForwarder note = NotedNote();
    note.invoice_id.clear();
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotForwarderResult result = modelnet::SwarmNoteNotForwarder(note, err);
    BOOST_CHECK_EQUAL(result.code, "INVOICE");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK_EQUAL(err, "INVOICE");
}

BOOST_AUTO_TEST_CASE(want_charge_is_not_charged)
{
    modelnet::SwarmNotForwarder note = NotedNote();
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotForwarderResult result = modelnet::SwarmNoteNotForwarder(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_CHARGED");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK_EQUAL(err, "NOT_CHARGED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotForwarder note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotForwarderResult result = modelnet::SwarmNoteNotForwarder(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
