// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoslots2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoslots2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotNoSlots2 note;
    note.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSlots2Result result = modelnet::SwarmNoteNotNoSlots2(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_raise_is_held)
{
    modelnet::SwarmNotNoSlots2 note;
    note.node_id = "node-1";
    note.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSlots2Result result = modelnet::SwarmNoteNotNoSlots2(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSlots2 note;
    note.node_id = "node-1";
    note.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSlots2Result result = modelnet::SwarmNoteNotNoSlots2(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.slots, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
