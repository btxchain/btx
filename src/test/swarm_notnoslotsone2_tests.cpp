// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoslotsone2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoslotsone2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSlotsOne2 note;
    note.no_device = true;
    note.want_raise = true;
    const modelnet::SwarmNotNoSlotsOne2Result result = modelnet::SwarmNoteNotNoSlotsOne2(note, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.slots, 1);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(no_device_is_slots_one)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSlotsOne2 note;
    note.node_id = "node-1";
    note.no_device = true;
    note.want_raise = false;
    const modelnet::SwarmNotNoSlotsOne2Result result = modelnet::SwarmNoteNotNoSlotsOne2(note, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.slots, 1);
    BOOST_CHECK_EQUAL(result.code, "SLOTS_ONE");
    BOOST_CHECK_EQUAL(err, "SLOTS_ONE");
}

BOOST_AUTO_TEST_CASE(want_raise_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSlotsOne2 note;
    note.node_id = "node-1";
    note.no_device = false;
    note.want_raise = true;
    const modelnet::SwarmNotNoSlotsOne2Result result = modelnet::SwarmNoteNotNoSlotsOne2(note, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.slots, 1);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSlotsOne2 note;
    note.node_id = "node-1";
    note.no_device = false;
    note.want_raise = false;
    const modelnet::SwarmNotNoSlotsOne2Result result = modelnet::SwarmNoteNotNoSlotsOne2(note, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.slots, 1);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
