// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofwdfee2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofwdfee2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoFwdFee2 NotedNote()
{
    modelnet::SwarmNotNoFwdFee2 note;
    note.edge_id = "edge-1";
    note.forwarder = false;
    note.want_charge = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_edge_id)
{
    modelnet::SwarmNotNoFwdFee2 note = NotedNote();
    note.edge_id.clear();
    note.forwarder = true;
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFwdFee2Result result = modelnet::SwarmNoteNotNoFwdFee2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "EDGE");
    BOOST_CHECK_EQUAL(err, "EDGE");
}

BOOST_AUTO_TEST_CASE(forwarder_true_want_charge_false)
{
    modelnet::SwarmNotNoFwdFee2 note = NotedNote();
    note.forwarder = true;
    note.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFwdFee2Result result = modelnet::SwarmNoteNotNoFwdFee2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_CHARGED");
    BOOST_CHECK_EQUAL(err, "NOT_CHARGED");
}

BOOST_AUTO_TEST_CASE(want_charge_true_forwarder_false)
{
    modelnet::SwarmNotNoFwdFee2 note = NotedNote();
    note.edge_id = "edge-2";
    note.forwarder = false;
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFwdFee2Result result = modelnet::SwarmNoteNotNoFwdFee2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_noted)
{
    modelnet::SwarmNotNoFwdFee2 note = NotedNote();
    note.edge_id = "edge-2";
    note.forwarder = false;
    note.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFwdFee2Result result = modelnet::SwarmNoteNotNoFwdFee2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
