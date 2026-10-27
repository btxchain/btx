// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/swarm_agentrun.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_agentrun_tool_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_digest_is_tool_before_private)
{
    modelnet::SwarmAgentRun plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.ReuseTool("", false, err));
    BOOST_REQUIRE_EQUAL(err, "TOOL");
    BOOST_REQUIRE_EQUAL(plane.tool_count(), 0u);
    BOOST_REQUIRE(!plane.tool(""));

    err = "prior";
    BOOST_REQUIRE(!plane.ReuseTool("", true, err));
    BOOST_REQUIRE_EQUAL(err, "TOOL");
    BOOST_REQUIRE_EQUAL(plane.tool_count(), 0u);
    BOOST_REQUIRE(plane.Trace().empty());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(private_digest_stores_nothing)
{
    modelnet::SwarmAgentRun plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.ReuseTool("digest-priv", true, err));
    BOOST_REQUIRE_EQUAL(err, "PRIVATE_DATA");
    BOOST_REQUIRE_EQUAL(plane.tool_count(), 0u);
    BOOST_REQUIRE(!plane.tool("digest-priv"));
    BOOST_REQUIRE(plane.Trace().empty());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(public_digest_is_stored_once_and_lookup_returns_true)
{
    modelnet::SwarmAgentRun plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.ReuseTool("digest-pub", false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.tool_count(), 1u);
    BOOST_REQUIRE(plane.tool("digest-pub"));
    BOOST_REQUIRE(!plane.tool("other"));

    err = "prior";
    BOOST_REQUIRE(!plane.ReuseTool("digest-pub", false, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.tool_count(), 1u);
    BOOST_REQUIRE(plane.tool("digest-pub"));

    err = "prior";
    BOOST_REQUIRE(!plane.ReuseTool("digest-pub", true, err));
    BOOST_REQUIRE_EQUAL(err, "PRIVATE_DATA");
    BOOST_REQUIRE(plane.tool("digest-pub"));
    BOOST_REQUIRE_EQUAL(plane.tool_count(), 1u);

    BOOST_REQUIRE(plane.ReuseTool("digest-b", false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.tool_count(), 2u);
    BOOST_REQUIRE(plane.tool("digest-b"));
    BOOST_REQUIRE(plane.tool("digest-pub"));

    const std::vector<std::string> trace = plane.Trace();
    BOOST_REQUIRE_EQUAL(trace.size(), 2u);
    BOOST_REQUIRE_EQUAL(trace[0], "ReuseTool");
    BOOST_REQUIRE_EQUAL(trace[1], "ReuseTool");
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
