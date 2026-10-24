// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notscripthop.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notscripthop_tests, BasicTestingSetup)

static modelnet::SwarmNotScriptHop NotedNote()
{
    modelnet::SwarmNotScriptHop note;
    note.invoice_id = "invoice-1";
    note.want_qualify = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_invoice_id_is_invoice)
{
    modelnet::SwarmNotScriptHop note = NotedNote();
    note.invoice_id.clear();
    note.want_qualify = true;
    std::string err = "prior";
    const modelnet::SwarmNotScriptHopResult result = modelnet::SwarmNoteNotScriptHop(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "INVOICE");
    BOOST_CHECK_EQUAL(err, "INVOICE");
}

BOOST_AUTO_TEST_CASE(want_qualify_is_unqualified)
{
    modelnet::SwarmNotScriptHop note = NotedNote();
    note.want_qualify = true;
    std::string err = "prior";
    const modelnet::SwarmNotScriptHopResult result = modelnet::SwarmNoteNotScriptHop(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotScriptHop note = NotedNote();
    note.want_qualify = false;
    std::string err = "prior";
    const modelnet::SwarmNotScriptHopResult result = modelnet::SwarmNoteNotScriptHop(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.multihop);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
