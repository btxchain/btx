// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogovmeter.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnogovmeter_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotNoGovMeter note;
    note.metered = true;
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovMeterResult result = modelnet::SwarmNoteNotNoGovMeter(note, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(metered)
{
    modelnet::SwarmNotNoGovMeter note;
    note.node_id = "node-1";
    note.metered = true;
    note.want_run = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovMeterResult result = modelnet::SwarmNoteNotNoGovMeter(note, err);
    BOOST_CHECK_EQUAL(result.code, "ZERO");
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(err, "ZERO");
}

BOOST_AUTO_TEST_CASE(want_run)
{
    modelnet::SwarmNotNoGovMeter note;
    note.node_id = "node-1";
    note.metered = false;
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovMeterResult result = modelnet::SwarmNoteNotNoGovMeter(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoGovMeter note;
    note.node_id = "node-1";
    note.metered = false;
    note.want_run = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovMeterResult result = modelnet::SwarmNoteNotNoGovMeter(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
