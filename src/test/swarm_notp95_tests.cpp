// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notp95.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notp95_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_latency)
{
    modelnet::SwarmNotP95 note;
    std::string err = "prior";
    const modelnet::SwarmNotP95Result result = modelnet::SwarmNoteNotP95(note, err);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.code, "LATENCY");
    BOOST_CHECK_EQUAL(err, "LATENCY");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    modelnet::SwarmNotP95 note;
    note.node_id = "node-a";
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotP95Result result = modelnet::SwarmNoteNotP95(note, err);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotP95 note;
    note.node_id = "node-a";
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotP95Result result = modelnet::SwarmNoteNotP95(note, err);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
