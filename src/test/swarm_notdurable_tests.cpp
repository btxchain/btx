// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdurable.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notdurable_tests, BasicTestingSetup)

static modelnet::SwarmNotDurable NotedNote()
{
    modelnet::SwarmNotDurable note;
    note.state_id = "state-1";
    note.want_persist = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_state_id_is_state)
{
    modelnet::SwarmNotDurable note = NotedNote();
    note.state_id.clear();
    note.want_persist = true;
    std::string err = "prior";
    const modelnet::SwarmNotDurableResult result = modelnet::SwarmNoteNotDurable(note, err);
    BOOST_CHECK(!result.persisted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "STATE");
    BOOST_CHECK_EQUAL(err, "STATE");
}

BOOST_AUTO_TEST_CASE(want_persist_is_not_persisted)
{
    modelnet::SwarmNotDurable note = NotedNote();
    note.want_persist = true;
    std::string err = "prior";
    const modelnet::SwarmNotDurableResult result = modelnet::SwarmNoteNotDurable(note, err);
    BOOST_CHECK(!result.persisted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_PERSISTED");
    BOOST_CHECK_EQUAL(err, "NOT_PERSISTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotDurable note = NotedNote();
    note.want_persist = false;
    std::string err = "prior";
    const modelnet::SwarmNotDurableResult result = modelnet::SwarmNoteNotDurable(note, err);
    BOOST_CHECK(!result.persisted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
