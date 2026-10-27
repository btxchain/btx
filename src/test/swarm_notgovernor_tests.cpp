// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notgovernor.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notgovernor_tests, BasicTestingSetup)

static modelnet::SwarmNotGovernor NotedNote()
{
    modelnet::SwarmNotGovernor note;
    note.node_id = "node-1";
    note.idle_off = false;
    note.battery = false;
    note.thermal = false;
    note.metered = false;
    note.want_keep = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotGovernor note = NotedNote();
    note.node_id.clear();
    note.idle_off = true;
    note.want_keep = true;
    std::string err = "prior";
    const modelnet::SwarmNotGovernorResult result = modelnet::SwarmNoteNotGovernor(note, err);
    BOOST_CHECK(!result.drained);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(idle_off_is_drain)
{
    modelnet::SwarmNotGovernor note = NotedNote();
    note.idle_off = true;
    note.want_keep = false;
    std::string err = "prior";
    const modelnet::SwarmNotGovernorResult result = modelnet::SwarmNoteNotGovernor(note, err);
    BOOST_CHECK(!result.drained);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "DRAIN");
    BOOST_CHECK_EQUAL(err, "DRAIN");
}

BOOST_AUTO_TEST_CASE(battery_is_drain)
{
    modelnet::SwarmNotGovernor note = NotedNote();
    note.battery = true;
    note.want_keep = false;
    std::string err = "prior";
    const modelnet::SwarmNotGovernorResult result = modelnet::SwarmNoteNotGovernor(note, err);
    BOOST_CHECK(!result.drained);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "DRAIN");
    BOOST_CHECK_EQUAL(err, "DRAIN");
}

BOOST_AUTO_TEST_CASE(thermal_is_drain)
{
    modelnet::SwarmNotGovernor note = NotedNote();
    note.thermal = true;
    note.want_keep = false;
    std::string err = "prior";
    const modelnet::SwarmNotGovernorResult result = modelnet::SwarmNoteNotGovernor(note, err);
    BOOST_CHECK(!result.drained);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "DRAIN");
    BOOST_CHECK_EQUAL(err, "DRAIN");
}

BOOST_AUTO_TEST_CASE(metered_is_drain)
{
    modelnet::SwarmNotGovernor note = NotedNote();
    note.metered = true;
    note.want_keep = false;
    std::string err = "prior";
    const modelnet::SwarmNotGovernorResult result = modelnet::SwarmNoteNotGovernor(note, err);
    BOOST_CHECK(!result.drained);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "DRAIN");
    BOOST_CHECK_EQUAL(err, "DRAIN");
}

BOOST_AUTO_TEST_CASE(want_keep_is_drain)
{
    modelnet::SwarmNotGovernor note = NotedNote();
    note.want_keep = true;
    std::string err = "prior";
    const modelnet::SwarmNotGovernorResult result = modelnet::SwarmNoteNotGovernor(note, err);
    BOOST_CHECK(!result.drained);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "DRAIN");
    BOOST_CHECK_EQUAL(err, "DRAIN");
}

BOOST_AUTO_TEST_CASE(plain_node_is_noted)
{
    modelnet::SwarmNotGovernor note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotGovernorResult result = modelnet::SwarmNoteNotGovernor(note, err);
    BOOST_CHECK(!result.drained);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
