// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmedium.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notmedium_tests, BasicTestingSetup)

static modelnet::SwarmNotMedium NotedNote()
{
    modelnet::SwarmNotMedium note;
    note.adapter_id = "adapter-1";
    note.want_execute = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_adapter_id_is_adapter)
{
    modelnet::SwarmNotMedium note = NotedNote();
    note.adapter_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotMediumResult result = modelnet::SwarmNoteNotMedium(note, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "ADAPTER");
    BOOST_CHECK_EQUAL(err, "ADAPTER");
}

BOOST_AUTO_TEST_CASE(want_execute_is_not_executed)
{
    modelnet::SwarmNotMedium note = NotedNote();
    note.want_execute = true;
    std::string err = "prior";
    const modelnet::SwarmNotMediumResult result = modelnet::SwarmNoteNotMedium(note, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOT_EXECUTED");
    BOOST_CHECK_EQUAL(err, "NOT_EXECUTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotMedium note = NotedNote();
    note.want_execute = false;
    std::string err = "prior";
    const modelnet::SwarmNotMediumResult result = modelnet::SwarmNoteNotMedium(note, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
