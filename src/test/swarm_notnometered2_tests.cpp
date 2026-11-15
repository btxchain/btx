// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnometered2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnometered2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMetered2 note;
    note.metered = true;
    note.want_run = true;
    const modelnet::SwarmNotNoMetered2Result result = modelnet::SwarmNoteNotNoMetered2(note, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(metered)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMetered2 note;
    note.node_id = "node-1";
    note.metered = true;
    note.want_run = false;
    const modelnet::SwarmNotNoMetered2Result result = modelnet::SwarmNoteNotNoMetered2(note, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "DRAINED");
    BOOST_CHECK_EQUAL(err, "DRAINED");
}

BOOST_AUTO_TEST_CASE(want_run)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMetered2 note;
    note.node_id = "node-1";
    note.metered = false;
    note.want_run = true;
    const modelnet::SwarmNotNoMetered2Result result = modelnet::SwarmNoteNotNoMetered2(note, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMetered2 note;
    note.node_id = "node-1";
    note.metered = false;
    note.want_run = false;
    const modelnet::SwarmNotNoMetered2Result result = modelnet::SwarmNoteNotNoMetered2(note, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
