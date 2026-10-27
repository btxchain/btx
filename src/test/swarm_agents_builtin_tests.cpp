// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/plane.h>
#include <modelnet/training_integer.h>
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

BOOST_FIXTURE_TEST_SUITE(swarm_agents_builtin_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hold_runs_in_the_caller)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Run(BaseRequest("hold-1", "hold"), err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.ran("hold-1"));
    BOOST_REQUIRE(plane.has_result("hold-1"));
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.step("hold-1"), 0);
    BOOST_REQUIRE_EQUAL(plane.result_hash("hold-1"), "hold");

    err = "prior";
    BOOST_CHECK(!plane.Run(BaseRequest("hold-1", "hold"), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.result_hash("hold-1"), "hold");
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(integer_step_stores_step_one_without_launch)
{
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8);

    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Run(BaseRequest("step-1", "integer-step"), err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.ran("step-1"));
    BOOST_REQUIRE(plane.has_result("step-1"));
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.step("step-1"), 1);
    BOOST_REQUIRE(!plane.result_hash("step-1").empty());

    modelnet::IntegerTrainer trainer;
    std::string step_err;
    BOOST_REQUIRE(trainer.Step(step_err));
    BOOST_REQUIRE(step_err.empty());
    BOOST_REQUIRE_EQUAL(trainer.State().step, 1);
    BOOST_REQUIRE_EQUAL(plane.result_hash("step-1"), trainer.State().state_hash);
    std::string replay_err;
    BOOST_REQUIRE(trainer.ReplayMatches(trainer.State(), replay_err));
    BOOST_REQUIRE(replay_err.empty());
}

BOOST_AUTO_TEST_CASE(unknown_kind_does_not_run)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_CHECK(!plane.Run(BaseRequest("other", "shell"), err));
    BOOST_CHECK_EQUAL(err, "UNKNOWN");
    BOOST_CHECK(!plane.ran("other"));
    BOOST_CHECK(!plane.has_result("other"));
    BOOST_CHECK(plane.result_hash("other").empty());
    BOOST_CHECK(!plane.launched());

    err = "prior";
    BOOST_CHECK(!plane.Run(BaseRequest("blank", ""), err));
    BOOST_CHECK_EQUAL(err, "UNKNOWN");
    BOOST_CHECK(!plane.has_result("blank"));
    BOOST_CHECK(!plane.launched());
}

BOOST_AUTO_TEST_CASE(network_refusal_of_integer_step_leaves_launched_false)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    modelnet::SwarmAgentRunRequest request = BaseRequest("step-net", "integer-step");
    request.network = true;

    BOOST_CHECK(!plane.Run(request, err));
    BOOST_CHECK_EQUAL(err, "NETWORK");
    BOOST_CHECK(!plane.ran("step-net"));
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.has_result("step-net"));
    BOOST_CHECK_EQUAL(plane.step("step-net"), 0);
    BOOST_CHECK(plane.result_hash("step-net").empty());
}

BOOST_AUTO_TEST_CASE(empty_task_stores_nothing)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_CHECK(!plane.Run(BaseRequest("", "hold"), err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_CHECK(!plane.ran(""));
    BOOST_CHECK(!plane.has_result(""));
    BOOST_CHECK(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
