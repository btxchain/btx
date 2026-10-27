// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notoneproc.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notoneproc_tests, BasicTestingSetup)

static modelnet::SwarmNotOneProc NotedNote()
{
    modelnet::SwarmNotOneProc note;
    note.log_id = "log-1";
    note.want_cluster = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_log_id_is_log)
{
    modelnet::SwarmNotOneProc note = NotedNote();
    note.log_id.clear();
    note.want_cluster = true;
    std::string err = "prior";
    const modelnet::SwarmNotOneProcResult result = modelnet::SwarmNoteNotOneProc(note, err);
    BOOST_CHECK(!result.clustered);
    BOOST_CHECK_EQUAL(result.peers, 0);
    BOOST_CHECK_EQUAL(result.code, "LOG");
    BOOST_CHECK_EQUAL(err, "LOG");
}

BOOST_AUTO_TEST_CASE(want_cluster_is_one_process)
{
    modelnet::SwarmNotOneProc note = NotedNote();
    note.want_cluster = true;
    std::string err = "prior";
    const modelnet::SwarmNotOneProcResult result = modelnet::SwarmNoteNotOneProc(note, err);
    BOOST_CHECK(!result.clustered);
    BOOST_CHECK_EQUAL(result.peers, 0);
    BOOST_CHECK_EQUAL(result.code, "ONE_PROCESS");
    BOOST_CHECK_EQUAL(err, "ONE_PROCESS");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotOneProc note = NotedNote();
    note.want_cluster = false;
    std::string err = "prior";
    const modelnet::SwarmNotOneProcResult result = modelnet::SwarmNoteNotOneProc(note, err);
    BOOST_CHECK(!result.clustered);
    BOOST_CHECK_EQUAL(result.peers, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
