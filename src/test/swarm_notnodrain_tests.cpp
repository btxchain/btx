// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodrain.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnodrain_tests, BasicTestingSetup)

static modelnet::SwarmNotNoDrain NotedNote()
{
    modelnet::SwarmNotNoDrain note;
    note.node_id = "node-1";
    note.idle_off = false;
    note.battery = false;
    note.thermal = false;
    note.metered = false;
    note.want_run = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty)
{
    modelnet::SwarmNotNoDrain note = NotedNote();
    note.node_id.clear();
    note.idle_off = true;
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDrainResult result = modelnet::SwarmNoteNotNoDrain(note, err);
    BOOST_CHECK_EQUAL(result.running, false);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(idle_off)
{
    modelnet::SwarmNotNoDrain note = NotedNote();
    note.idle_off = true;
    note.battery = false;
    note.thermal = false;
    note.metered = false;
    note.want_run = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDrainResult result = modelnet::SwarmNoteNotNoDrain(note, err);
    BOOST_CHECK_EQUAL(result.running, false);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "DRAINED");
    BOOST_CHECK_EQUAL(err, "DRAINED");
}

BOOST_AUTO_TEST_CASE(want_run)
{
    modelnet::SwarmNotNoDrain note = NotedNote();
    note.idle_off = false;
    note.battery = false;
    note.thermal = false;
    note.metered = false;
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDrainResult result = modelnet::SwarmNoteNotNoDrain(note, err);
    BOOST_CHECK_EQUAL(result.running, false);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(plain)
{
    modelnet::SwarmNotNoDrain note = NotedNote();
    note.idle_off = false;
    note.battery = false;
    note.thermal = false;
    note.metered = false;
    note.want_run = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDrainResult result = modelnet::SwarmNoteNotNoDrain(note, err);
    BOOST_CHECK_EQUAL(result.running, false);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
