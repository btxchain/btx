// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogovbat.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnogovbat_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotNoGovBat note;
    note.battery = true;
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovBatResult result = modelnet::SwarmNoteNotNoGovBat(note, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(battery)
{
    modelnet::SwarmNotNoGovBat note;
    note.node_id = "node-1";
    note.battery = true;
    note.want_run = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovBatResult result = modelnet::SwarmNoteNotNoGovBat(note, err);
    BOOST_CHECK_EQUAL(result.code, "ZERO");
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(err, "ZERO");
}

BOOST_AUTO_TEST_CASE(want_run)
{
    modelnet::SwarmNotNoGovBat note;
    note.node_id = "node-1";
    note.battery = false;
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovBatResult result = modelnet::SwarmNoteNotNoGovBat(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoGovBat note;
    note.node_id = "node-1";
    note.battery = false;
    note.want_run = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovBatResult result = modelnet::SwarmNoteNotNoGovBat(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
