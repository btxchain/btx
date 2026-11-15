// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoexec.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoexec_tests, BasicTestingSetup)

static modelnet::SwarmNotNoExec NotedNote()
{
    modelnet::SwarmNotNoExec note;
    note.sandbox_id = "sandbox-1";
    note.want_exec = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_sandbox_id_is_sandbox)
{
    modelnet::SwarmNotNoExec note = NotedNote();
    note.sandbox_id.clear();
    note.want_exec = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoExecResult result = modelnet::SwarmNoteNotNoExec(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "SANDBOX");
    BOOST_CHECK_EQUAL(err, "SANDBOX");
}

BOOST_AUTO_TEST_CASE(want_exec_is_not_launched)
{
    modelnet::SwarmNotNoExec note = NotedNote();
    note.want_exec = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoExecResult result = modelnet::SwarmNoteNotNoExec(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_LAUNCHED");
    BOOST_CHECK_EQUAL(err, "NOT_LAUNCHED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoExec note = NotedNote();
    note.want_exec = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoExecResult result = modelnet::SwarmNoteNotNoExec(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
