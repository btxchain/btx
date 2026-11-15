// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmcp.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notmcp_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_adapter_id)
{
    modelnet::SwarmNotMcp note;
    note.want_connect = true;
    std::string err = "stale";
    const modelnet::SwarmNotMcpResult result = modelnet::SwarmNoteNotMcp(note, err);
    BOOST_CHECK_EQUAL(result.code, "ADAPTER");
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(err, "ADAPTER");
}

BOOST_AUTO_TEST_CASE(want_connect_not_connected)
{
    modelnet::SwarmNotMcp note;
    note.adapter_id = "adapter-a";
    note.want_connect = true;
    std::string err = "stale";
    const modelnet::SwarmNotMcpResult result = modelnet::SwarmNoteNotMcp(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_CONNECTED");
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(err, "NOT_CONNECTED");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmNotMcp note;
    note.adapter_id = "adapter-a";
    std::string err = "stale";
    const modelnet::SwarmNotMcpResult result = modelnet::SwarmNoteNotMcp(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
