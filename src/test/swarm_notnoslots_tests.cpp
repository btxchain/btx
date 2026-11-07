// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoslots.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoslots_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSlots note;
    note.slots = 2;
    note.want_open = true;
    const modelnet::SwarmNotNoSlotsResult result = modelnet::SwarmNoteNotNoSlots(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.applied, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(slots_not_one_is_capped)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSlots note;
    note.node_id = "node-1";
    note.slots = 2;
    note.want_open = false;
    const modelnet::SwarmNotNoSlotsResult result = modelnet::SwarmNoteNotNoSlots(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.applied, 0);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_open_at_one_is_capped)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSlots note;
    note.node_id = "node-1";
    note.slots = 1;
    note.want_open = true;
    const modelnet::SwarmNotNoSlotsResult result = modelnet::SwarmNoteNotNoSlots(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.applied, 0);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(plain_one_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSlots note;
    note.node_id = "node-1";
    note.slots = 1;
    note.want_open = false;
    const modelnet::SwarmNotNoSlotsResult result = modelnet::SwarmNoteNotNoSlots(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.applied, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
