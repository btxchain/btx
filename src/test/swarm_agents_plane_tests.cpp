// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/plane.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

static bool Contains(const std::vector<std::string>& ids, const std::string& id)
{
    for (const std::string& cur : ids) {
        if (cur == id) {
            return true;
        }
    }
    return false;
}

static modelnet::SwarmAgentRunRequest BaseRequest(const std::string& task, const std::string& kind)
{
    modelnet::SwarmAgentRunRequest request;
    request.task = task;
    request.kind = kind;
    request.network = false;
    request.host_interpreter = false;
    request.requested_threads = 2;
    request.requested_mib = 64;
    request.sandbox_root = "/sandbox/";
    request.path = "/sandbox/work/step";
    return request;
}

BOOST_FIXTURE_TEST_SUITE(swarm_agents_plane_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(three_task_chain_cancel_middle_blocks_the_last)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Add("fetch", {}, err));
    BOOST_REQUIRE(plane.Add("train", {"fetch"}, err));
    BOOST_REQUIRE(plane.Add("publish", {"train"}, err));
    BOOST_REQUIRE(err.empty());

    const std::vector<std::string> before = plane.Ready();
    BOOST_REQUIRE_EQUAL(before.size(), 1);
    BOOST_REQUIRE_EQUAL(before[0], "fetch");
    BOOST_REQUIRE(!Contains(before, "publish"));

    BOOST_REQUIRE(plane.Commit("fetch", "hash-fetch", err));
    const std::vector<std::string> mid = plane.Ready();
    BOOST_REQUIRE_EQUAL(mid.size(), 1);
    BOOST_REQUIRE_EQUAL(mid[0], "train");

    BOOST_REQUIRE(plane.Cancel("train", err));
    BOOST_REQUIRE(err.empty());

    const std::vector<std::string> after = plane.Ready();
    BOOST_REQUIRE(after.empty());
    BOOST_REQUIRE(!Contains(after, "train"));
    BOOST_REQUIRE(!Contains(after, "publish"));

    err = "prior";
    BOOST_CHECK(!plane.Commit("publish", "hash-publish", err));
    BOOST_CHECK_EQUAL(err, "NOT_READY");
    BOOST_CHECK(plane.CommittedHash("publish").empty());
    BOOST_REQUIRE(!Contains(plane.Ready(), "publish"));

    err = "prior";
    BOOST_CHECK(!plane.Commit("train", "hash-train", err));
    BOOST_CHECK_EQUAL(err, "CANCELLED");
    BOOST_REQUIRE(!Contains(plane.Ready(), "publish"));

    const std::vector<modelnet::SwarmAgentTraceRow> rows = plane.Trace();
    BOOST_REQUIRE_EQUAL(rows.size(), 2);
    BOOST_REQUIRE_EQUAL(rows[0].task, "fetch");
    BOOST_REQUIRE_EQUAL(rows[0].event, "commit");
    BOOST_REQUIRE_EQUAL(rows[1].task, "train");
    BOOST_REQUIRE_EQUAL(rows[1].event, "cancel");
}

BOOST_AUTO_TEST_CASE(integer_step_succeeds_and_network_refusal_does_not_launch)
{
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8);

    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Run(BaseRequest("step", "integer-step"), err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.ran("step"));
    BOOST_REQUIRE(plane.has_result("step"));
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.step("step"), 1);
    BOOST_REQUIRE(!plane.result_hash("step").empty());

    modelnet::IntegerTrainer trainer;
    std::string step_err;
    BOOST_REQUIRE(trainer.Step(step_err));
    BOOST_REQUIRE_EQUAL(trainer.State().step, 1);
    std::string replay_err;
    BOOST_REQUIRE(trainer.ReplayMatches(trainer.State(), replay_err));
    BOOST_REQUIRE_EQUAL(plane.result_hash("step"), trainer.State().state_hash);

    err = "prior";
    modelnet::SwarmAgentRunRequest refused = BaseRequest("step-net", "integer-step");
    refused.network = true;
    BOOST_CHECK(!plane.Run(refused, err));
    BOOST_CHECK_EQUAL(err, "NETWORK");
    BOOST_CHECK(!plane.ran("step-net"));
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.has_result("step-net"));
    BOOST_CHECK_EQUAL(plane.step("step-net"), 0);
    BOOST_CHECK(plane.result_hash("step-net").empty());

    BOOST_REQUIRE(plane.ran("step"));
    BOOST_REQUIRE_EQUAL(plane.step("step"), 1);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(refused_runs_leave_no_result_beside_a_hold)
{
    modelnet::SwarmAgentPlane plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Run(BaseRequest("kept", "hold"), err));
    BOOST_REQUIRE(plane.ran("kept"));
    BOOST_REQUIRE(!plane.launched());

    modelnet::SwarmAgentRunRequest host = BaseRequest("host", "hold");
    host.host_interpreter = true;
    BOOST_CHECK(!plane.Run(host, err));
    BOOST_CHECK_EQUAL(err, "HOST");

    modelnet::SwarmAgentRunRequest capped = BaseRequest("capped", "integer-step");
    capped.requested_threads = 65;
    BOOST_CHECK(!plane.Run(capped, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");

    modelnet::SwarmAgentRunRequest escaped = BaseRequest("escaped", "integer-step");
    escaped.path = "/sandbox/../secret";
    BOOST_CHECK(!plane.Run(escaped, err));
    BOOST_CHECK_EQUAL(err, "ESCAPE");

    modelnet::SwarmAgentRunRequest unknown = BaseRequest("unknown", "other");
    BOOST_CHECK(!plane.Run(unknown, err));
    BOOST_CHECK_EQUAL(err, "UNKNOWN");

    BOOST_CHECK(!plane.has_result("host"));
    BOOST_CHECK(!plane.has_result("capped"));
    BOOST_CHECK(!plane.has_result("escaped"));
    BOOST_CHECK(!plane.has_result("unknown"));
    BOOST_CHECK(!plane.launched());
    BOOST_REQUIRE(plane.has_result("kept"));
    BOOST_REQUIRE_EQUAL(plane.result_hash("kept"), "hold");
}

BOOST_AUTO_TEST_SUITE_END()
