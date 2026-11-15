// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notwindows.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notwindows_tests, BasicTestingSetup)

static modelnet::SwarmNotWindows NotedNote()
{
    modelnet::SwarmNotWindows note;
    note.node_id = "node-1";
    note.want_pass = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_windows)
{
    modelnet::SwarmNotWindows note = NotedNote();
    note.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotWindowsResult result = modelnet::SwarmNoteNotWindows(note, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "WINDOWS");
    BOOST_CHECK_EQUAL(err, "WINDOWS");
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmNotWindows note = NotedNote();
    note.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmNotWindowsResult result = modelnet::SwarmNoteNotWindows(note, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotWindows note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotWindowsResult result = modelnet::SwarmNoteNotWindows(note, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
