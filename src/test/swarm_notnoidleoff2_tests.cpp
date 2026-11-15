// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoidleoff2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoidleoff2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotNoIdleOff2 note;
    note.idle_off = true;
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoIdleOff2Result result = modelnet::SwarmNoteNotNoIdleOff2(note, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(idle_off)
{
    modelnet::SwarmNotNoIdleOff2 note;
    note.node_id = "node-1";
    note.idle_off = true;
    note.want_run = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoIdleOff2Result result = modelnet::SwarmNoteNotNoIdleOff2(note, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "DRAINED");
    BOOST_CHECK_EQUAL(err, "DRAINED");
}

BOOST_AUTO_TEST_CASE(want_run)
{
    modelnet::SwarmNotNoIdleOff2 note;
    note.node_id = "node-1";
    note.idle_off = false;
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoIdleOff2Result result = modelnet::SwarmNoteNotNoIdleOff2(note, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoIdleOff2 note;
    note.node_id = "node-1";
    note.idle_off = false;
    note.want_run = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoIdleOff2Result result = modelnet::SwarmNoteNotNoIdleOff2(note, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
