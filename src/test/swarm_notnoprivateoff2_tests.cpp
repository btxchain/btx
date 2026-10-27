// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprivateoff2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoprivateoff2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_yields_node)
{
    modelnet::SwarmNotNoPrivateOff2 note;
    note.node_id.clear();
    note.no_device = false;
    note.want_enable = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoPrivateOff2Result result = modelnet::SwarmNoteNotNoPrivateOff2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
    BOOST_CHECK_EQUAL(result.enabled, false);
}

BOOST_AUTO_TEST_CASE(no_device_true_want_enable_false_yields_not_private)
{
    modelnet::SwarmNotNoPrivateOff2 note;
    note.node_id = "node-1";
    note.no_device = true;
    note.want_enable = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoPrivateOff2Result result = modelnet::SwarmNoteNotNoPrivateOff2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_PRIVATE");
    BOOST_CHECK_EQUAL(err, "NOT_PRIVATE");
    BOOST_CHECK_EQUAL(result.enabled, false);
}

BOOST_AUTO_TEST_CASE(want_enable_true_no_device_false_yields_held)
{
    modelnet::SwarmNotNoPrivateOff2 note;
    note.node_id = "node-1";
    note.no_device = false;
    note.want_enable = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoPrivateOff2Result result = modelnet::SwarmNoteNotNoPrivateOff2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(result.enabled, false);
}

BOOST_AUTO_TEST_CASE(neither_yields_noted_err_empty)
{
    modelnet::SwarmNotNoPrivateOff2 note;
    note.node_id = "node-1";
    note.no_device = false;
    note.want_enable = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoPrivateOff2Result result = modelnet::SwarmNoteNotNoPrivateOff2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(result.enabled, false);
}

BOOST_AUTO_TEST_SUITE_END()
