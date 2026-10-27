// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnixlabs.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnixlabs_tests, BasicTestingSetup)

static modelnet::SwarmNotNixlAbs NotedNote()
{
    modelnet::SwarmNotNixlAbs note;
    note.adapter_id = "adapter-1";
    note.want_move = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_adapter_id_is_adapter)
{
    modelnet::SwarmNotNixlAbs note = NotedNote();
    note.adapter_id.clear();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNixlAbsResult result = modelnet::SwarmNoteNotNixlAbs(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ADAPTER");
    BOOST_CHECK_EQUAL(err, "ADAPTER");
}

BOOST_AUTO_TEST_CASE(want_move_is_engine_absent)
{
    modelnet::SwarmNotNixlAbs note = NotedNote();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNixlAbsResult result = modelnet::SwarmNoteNotNixlAbs(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNixlAbs note = NotedNote();
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNixlAbsResult result = modelnet::SwarmNoteNotNixlAbs(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
