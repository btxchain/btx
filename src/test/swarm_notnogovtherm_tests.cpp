// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogovtherm.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnogovtherm_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotNoGovTherm note;
    note.thermal = true;
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovThermResult result = modelnet::SwarmNoteNotNoGovTherm(note, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(thermal)
{
    modelnet::SwarmNotNoGovTherm note;
    note.node_id = "node-1";
    note.thermal = true;
    note.want_run = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovThermResult result = modelnet::SwarmNoteNotNoGovTherm(note, err);
    BOOST_CHECK_EQUAL(result.code, "ZERO");
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(err, "ZERO");
}

BOOST_AUTO_TEST_CASE(want_run)
{
    modelnet::SwarmNotNoGovTherm note;
    note.node_id = "node-1";
    note.thermal = false;
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovThermResult result = modelnet::SwarmNoteNotNoGovTherm(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoGovTherm note;
    note.node_id = "node-1";
    note.thermal = false;
    note.want_run = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovThermResult result = modelnet::SwarmNoteNotNoGovTherm(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
