// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_slot1.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_slot1_tests, BasicTestingSetup)

static modelnet::SwarmDefaultSlots NotedSlots()
{
    modelnet::SwarmDefaultSlots note;
    note.node_id = "node-1";
    note.device_json_present = false;
    note.requested_slots = 1;
    note.want_launch = false;
    return note;
}

static void ExpectNotLaunched(const modelnet::SwarmDefaultSlotsResult& result, int64_t slots)
{
    BOOST_CHECK_EQUAL(result.slots, slots);
    BOOST_CHECK(!result.launched);
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_slots)
{
    modelnet::SwarmDefaultSlots note = NotedSlots();
    note.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmDefaultSlotsResult result = modelnet::SwarmNoteDefaultSlots(note, err);
    ExpectNotLaunched(result, 0);
    BOOST_CHECK_EQUAL(result.code, "SLOTS");
    BOOST_CHECK_EQUAL(err, "SLOTS");
}

BOOST_AUTO_TEST_CASE(empty_node_id_wins_over_present_count_and_launch)
{
    modelnet::SwarmDefaultSlots note = NotedSlots();
    note.node_id.clear();
    note.device_json_present = true;
    note.requested_slots = 4;
    note.want_launch = true;
    std::string err = "prior";
    const modelnet::SwarmDefaultSlotsResult result = modelnet::SwarmNoteDefaultSlots(note, err);
    ExpectNotLaunched(result, 0);
    BOOST_CHECK_EQUAL(result.code, "SLOTS");
    BOOST_CHECK_EQUAL(err, "SLOTS");
}

BOOST_AUTO_TEST_CASE(negative_requested_slots_is_slots)
{
    modelnet::SwarmDefaultSlots note = NotedSlots();
    note.requested_slots = -1;
    std::string err = "prior";
    const modelnet::SwarmDefaultSlotsResult result = modelnet::SwarmNoteDefaultSlots(note, err);
    ExpectNotLaunched(result, 0);
    BOOST_CHECK_EQUAL(result.code, "SLOTS");
    BOOST_CHECK_EQUAL(err, "SLOTS");
}

BOOST_AUTO_TEST_CASE(negative_requested_slots_wins_over_present_and_launch)
{
    modelnet::SwarmDefaultSlots note = NotedSlots();
    note.requested_slots = -1;
    note.device_json_present = true;
    note.want_launch = true;
    std::string err = "prior";
    const modelnet::SwarmDefaultSlotsResult result = modelnet::SwarmNoteDefaultSlots(note, err);
    ExpectNotLaunched(result, 0);
    BOOST_CHECK_EQUAL(result.code, "SLOTS");
    BOOST_CHECK_EQUAL(err, "SLOTS");
}

BOOST_AUTO_TEST_CASE(device_json_present_is_present)
{
    modelnet::SwarmDefaultSlots note = NotedSlots();
    note.device_json_present = true;
    std::string err = "prior";
    const modelnet::SwarmDefaultSlotsResult result = modelnet::SwarmNoteDefaultSlots(note, err);
    ExpectNotLaunched(result, 0);
    BOOST_CHECK_EQUAL(result.code, "PRESENT");
    BOOST_CHECK_EQUAL(err, "PRESENT");
}

BOOST_AUTO_TEST_CASE(device_json_present_wins_over_count_and_launch)
{
    modelnet::SwarmDefaultSlots note = NotedSlots();
    note.device_json_present = true;
    note.requested_slots = 0;
    note.want_launch = true;
    std::string err = "prior";
    const modelnet::SwarmDefaultSlotsResult result = modelnet::SwarmNoteDefaultSlots(note, err);
    ExpectNotLaunched(result, 0);
    BOOST_CHECK_EQUAL(result.code, "PRESENT");
    BOOST_CHECK_EQUAL(err, "PRESENT");
}

BOOST_AUTO_TEST_CASE(zero_requested_slots_is_not_default)
{
    modelnet::SwarmDefaultSlots note = NotedSlots();
    note.requested_slots = 0;
    std::string err = "prior";
    const modelnet::SwarmDefaultSlotsResult result = modelnet::SwarmNoteDefaultSlots(note, err);
    ExpectNotLaunched(result, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_DEFAULT");
    BOOST_CHECK_EQUAL(err, "NOT_DEFAULT");
}

BOOST_AUTO_TEST_CASE(requested_slots_above_one_is_not_default)
{
    modelnet::SwarmDefaultSlots note = NotedSlots();
    note.requested_slots = 2;
    std::string err = "prior";
    const modelnet::SwarmDefaultSlotsResult result = modelnet::SwarmNoteDefaultSlots(note, err);
    ExpectNotLaunched(result, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_DEFAULT");
    BOOST_CHECK_EQUAL(err, "NOT_DEFAULT");
}

BOOST_AUTO_TEST_CASE(not_default_wins_when_want_launch_is_true)
{
    modelnet::SwarmDefaultSlots note = NotedSlots();
    note.requested_slots = 3;
    note.want_launch = true;
    std::string err = "prior";
    const modelnet::SwarmDefaultSlotsResult result = modelnet::SwarmNoteDefaultSlots(note, err);
    ExpectNotLaunched(result, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_DEFAULT");
    BOOST_CHECK_EQUAL(err, "NOT_DEFAULT");
}

BOOST_AUTO_TEST_CASE(want_launch_is_held)
{
    modelnet::SwarmDefaultSlots note = NotedSlots();
    note.requested_slots = 1;
    note.want_launch = true;
    std::string err = "prior";
    const modelnet::SwarmDefaultSlotsResult result = modelnet::SwarmNoteDefaultSlots(note, err);
    ExpectNotLaunched(result, 1);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(absent_device_file_default_is_noted)
{
    modelnet::SwarmDefaultSlots note = NotedSlots();
    std::string err = "prior";
    const modelnet::SwarmDefaultSlotsResult result = modelnet::SwarmNoteDefaultSlots(note, err);
    ExpectNotLaunched(result, 1);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
