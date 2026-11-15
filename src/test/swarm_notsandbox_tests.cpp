// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsandbox.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notsandbox_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_executor_id_is_executor)
{
    std::string err = "prior";
    modelnet::SwarmNotSandbox note;
    note.want_launch = true;
    const modelnet::SwarmNotSandboxResult result = modelnet::SwarmNoteNotSandbox(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(!result.restricted);
    BOOST_CHECK_EQUAL(result.code, "EXECUTOR");
    BOOST_CHECK_EQUAL(err, "EXECUTOR");
}

BOOST_AUTO_TEST_CASE(want_launch_is_sandbox_absent)
{
    std::string err = "prior";
    modelnet::SwarmNotSandbox note;
    note.executor_id = "executor-1";
    note.want_launch = true;
    const modelnet::SwarmNotSandboxResult result = modelnet::SwarmNoteNotSandbox(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(!result.restricted);
    BOOST_CHECK_EQUAL(result.code, "SANDBOX_ABSENT");
    BOOST_CHECK_EQUAL(err, "SANDBOX_ABSENT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotSandbox note;
    note.executor_id = "executor-1";
    note.want_launch = false;
    const modelnet::SwarmNotSandboxResult result = modelnet::SwarmNoteNotSandbox(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(!result.restricted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
