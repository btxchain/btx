// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notinit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notinit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotInit note;
    note.want_init = true;
    note.want_shutdown = true;
    std::string err = "stale";
    const modelnet::SwarmNotInitResult result = modelnet::SwarmNoteNotInit(note, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.initialized);
    BOOST_CHECK(!result.shutdown);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_shutdown_not_shutdown)
{
    modelnet::SwarmNotInit note;
    note.node_id = "n1";
    note.want_init = true;
    note.want_shutdown = true;
    std::string err = "stale";
    const modelnet::SwarmNotInitResult result = modelnet::SwarmNoteNotInit(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_SHUTDOWN");
    BOOST_CHECK(!result.initialized);
    BOOST_CHECK(!result.shutdown);
    BOOST_CHECK_EQUAL(err, "NOT_SHUTDOWN");
}

BOOST_AUTO_TEST_CASE(want_init_not_init)
{
    modelnet::SwarmNotInit note;
    note.node_id = "n1";
    note.want_init = true;
    std::string err = "stale";
    const modelnet::SwarmNotInitResult result = modelnet::SwarmNoteNotInit(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_INIT");
    BOOST_CHECK(!result.initialized);
    BOOST_CHECK(!result.shutdown);
    BOOST_CHECK_EQUAL(err, "NOT_INIT");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmNotInit note;
    note.node_id = "n1";
    std::string err = "stale";
    const modelnet::SwarmNotInitResult result = modelnet::SwarmNoteNotInit(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.initialized);
    BOOST_CHECK(!result.shutdown);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
