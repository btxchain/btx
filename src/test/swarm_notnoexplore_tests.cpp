// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoexplore.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoexplore_tests, BasicTestingSetup)

static modelnet::SwarmNotNoExplore NotedNote()
{
    modelnet::SwarmNotNoExplore note;
    note.slot_id = "slot-1";
    note.want_assign = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_slot_id_is_slot)
{
    modelnet::SwarmNotNoExplore note = NotedNote();
    note.slot_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoExploreResult result = modelnet::SwarmNoteNotNoExplore(note, err);
    BOOST_CHECK(!result.assigned);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.code, "SLOT");
    BOOST_CHECK_EQUAL(err, "SLOT");
}

BOOST_AUTO_TEST_CASE(want_assign_is_not_assigned)
{
    modelnet::SwarmNotNoExplore note = NotedNote();
    note.want_assign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoExploreResult result = modelnet::SwarmNoteNotNoExplore(note, err);
    BOOST_CHECK(!result.assigned);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_ASSIGNED");
    BOOST_CHECK_EQUAL(err, "NOT_ASSIGNED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoExplore note = NotedNote();
    note.want_assign = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoExploreResult result = modelnet::SwarmNoteNotNoExplore(note, err);
    BOOST_CHECK(!result.assigned);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
