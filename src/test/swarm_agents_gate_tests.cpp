// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/plane.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

static modelnet::SwarmAgentRunRequest BaseRequest(const std::string& task, const std::string& kind)
{
    modelnet::SwarmAgentRunRequest request;
    request.task = task;
    request.kind = kind;
    request.network = false;
    request.host_interpreter = false;
    request.requested_threads = 1;
    request.requested_mib = 32;
    request.sandbox_root = "/sandbox/";
    request.path = "/sandbox/work";
    return request;
}

BOOST_FIXTURE_TEST_SUITE(swarm_agents_gate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(network_is_refused_and_stores_nothing)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    modelnet::SwarmAgentRunRequest request = BaseRequest("net", "hold");
    request.network = true;
    request.host_interpreter = true;
    request.requested_threads = 99;
    request.path = "/sandbox/../etc";

    BOOST_CHECK(!plane.Run(request, err));
    BOOST_CHECK_EQUAL(err, "NETWORK");
    BOOST_CHECK(!plane.ran("net"));
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.has_result("net"));
    BOOST_CHECK(plane.result_hash("net").empty());
    BOOST_CHECK_EQUAL(plane.step("net"), 0);
}

BOOST_AUTO_TEST_CASE(host_interpreter_is_refused_and_stores_nothing)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    modelnet::SwarmAgentRunRequest request = BaseRequest("host", "hold");
    request.host_interpreter = true;

    BOOST_CHECK(!plane.Run(request, err));
    BOOST_CHECK_EQUAL(err, "HOST");
    BOOST_CHECK(!plane.ran("host"));
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.has_result("host"));
    BOOST_CHECK(plane.result_hash("host").empty());
}

BOOST_AUTO_TEST_CASE(thread_and_memory_outside_the_window_are_capped)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";

    modelnet::SwarmAgentRunRequest high_threads = BaseRequest("threads", "hold");
    high_threads.requested_threads = 65;
    BOOST_CHECK(!plane.Run(high_threads, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK(!plane.has_result("threads"));
    BOOST_CHECK(!plane.launched());

    err = "prior";
    modelnet::SwarmAgentRunRequest low_threads = BaseRequest("threads-low", "hold");
    low_threads.requested_threads = -1;
    BOOST_CHECK(!plane.Run(low_threads, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK(!plane.has_result("threads-low"));

    err = "prior";
    modelnet::SwarmAgentRunRequest high_mib = BaseRequest("mib", "hold");
    high_mib.requested_mib = 16385;
    BOOST_CHECK(!plane.Run(high_mib, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK(!plane.has_result("mib"));

    err = "prior";
    modelnet::SwarmAgentRunRequest low_mib = BaseRequest("mib-low", "hold");
    low_mib.requested_mib = -1;
    BOOST_CHECK(!plane.Run(low_mib, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK(!plane.has_result("mib-low"));
    BOOST_CHECK(!plane.launched());
}

BOOST_AUTO_TEST_CASE(dotdot_and_foreign_prefix_are_escape)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";

    modelnet::SwarmAgentRunRequest dotdot = BaseRequest("dot", "hold");
    dotdot.path = "/sandbox/../etc";
    BOOST_CHECK(!plane.Run(dotdot, err));
    BOOST_CHECK_EQUAL(err, "ESCAPE");
    BOOST_CHECK(!plane.has_result("dot"));
    BOOST_CHECK(!plane.ran("dot"));
    BOOST_CHECK(!plane.launched());

    err = "prior";
    modelnet::SwarmAgentRunRequest nested = BaseRequest("nested", "hold");
    nested.path = "/sandbox/work/../../etc/passwd";
    BOOST_CHECK(!plane.Run(nested, err));
    BOOST_CHECK_EQUAL(err, "ESCAPE");
    BOOST_CHECK(!plane.has_result("nested"));

    err = "prior";
    modelnet::SwarmAgentRunRequest foreign = BaseRequest("foreign", "hold");
    foreign.path = "/other/a";
    BOOST_CHECK(!plane.Run(foreign, err));
    BOOST_CHECK_EQUAL(err, "ESCAPE");
    BOOST_CHECK(!plane.has_result("foreign"));

    err = "prior";
    modelnet::SwarmAgentRunRequest sibling = BaseRequest("sibling", "hold");
    sibling.path = "/sandbox-other/x";
    BOOST_CHECK(!plane.Run(sibling, err));
    BOOST_CHECK_EQUAL(err, "ESCAPE");
    BOOST_CHECK(!plane.has_result("sibling"));

    err = "prior";
    modelnet::SwarmAgentRunRequest bare_root = BaseRequest("bare", "hold");
    bare_root.sandbox_root = "/sandbox";
    bare_root.path = "/sandbox/work";
    BOOST_CHECK(!plane.Run(bare_root, err));
    BOOST_CHECK_EQUAL(err, "ESCAPE");
    BOOST_CHECK(!plane.has_result("bare"));
    BOOST_CHECK(!plane.launched());
}

BOOST_AUTO_TEST_CASE(inclusive_bounds_and_trailing_slash_root_run_hold)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    modelnet::SwarmAgentRunRequest request = BaseRequest("edge", "hold");
    request.requested_threads = 64;
    request.requested_mib = 16384;
    request.sandbox_root = "/sandbox/";
    request.path = "/sandbox/work";

    BOOST_REQUIRE(plane.Run(request, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.ran("edge"));
    BOOST_REQUIRE(plane.has_result("edge"));
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.result_hash("edge"), "hold");
    BOOST_REQUIRE_EQUAL(plane.step("edge"), 0);

    err = "prior";
    modelnet::SwarmAgentRunRequest zero = BaseRequest("zero", "hold");
    zero.requested_threads = 0;
    zero.requested_mib = 0;
    BOOST_REQUIRE(plane.Run(zero, err));
    BOOST_REQUIRE(plane.ran("zero"));
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
