// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomcp.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnomcp_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_tool_id)
{
    modelnet::SwarmNotNoMcp note;
    note.want_call = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoMcpResult result = modelnet::SwarmNoteNotNoMcp(note, err);
    BOOST_CHECK_EQUAL(result.code, "TOOL");
    BOOST_CHECK(!result.called);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "TOOL");
}

BOOST_AUTO_TEST_CASE(want_call_not_called)
{
    modelnet::SwarmNotNoMcp note;
    note.tool_id = "tool-a";
    note.want_call = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoMcpResult result = modelnet::SwarmNoteNotNoMcp(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_CALLED");
    BOOST_CHECK(!result.called);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "NOT_CALLED");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmNotNoMcp note;
    note.tool_id = "tool-a";
    std::string err = "stale";
    const modelnet::SwarmNotNoMcpResult result = modelnet::SwarmNoteNotNoMcp(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.called);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
