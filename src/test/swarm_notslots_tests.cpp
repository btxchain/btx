// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notslots.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notslots_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotSlots note;
    std::string err = "prior";
    const modelnet::SwarmNotSlotsResult result = modelnet::SwarmNoteNotSlots(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.applied_slots, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(slot_count_0)
{
    modelnet::SwarmNotSlots note;
    note.node_id = "node-1";
    note.slot_count = 0;
    note.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmNotSlotsResult result = modelnet::SwarmNoteNotSlots(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.applied_slots, 0);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(slot_count_2)
{
    modelnet::SwarmNotSlots note;
    note.node_id = "node-1";
    note.slot_count = 2;
    note.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmNotSlotsResult result = modelnet::SwarmNoteNotSlots(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.applied_slots, 0);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(slot_count_1_want_raise)
{
    modelnet::SwarmNotSlots note;
    note.node_id = "node-1";
    note.slot_count = 1;
    note.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmNotSlotsResult result = modelnet::SwarmNoteNotSlots(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.applied_slots, 0);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(slot_count_1_plain)
{
    modelnet::SwarmNotSlots note;
    note.node_id = "node-1";
    note.slot_count = 1;
    note.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmNotSlotsResult result = modelnet::SwarmNoteNotSlots(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.applied_slots, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
