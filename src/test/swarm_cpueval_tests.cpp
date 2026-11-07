// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cpueval.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cpueval_tests, BasicTestingSetup)

static modelnet::SwarmCpuEval NotedEval()
{
    modelnet::SwarmCpuEval eval;
    eval.node_id = "node-local";
    eval.cpu_available = true;
    eval.want_publish_rate = false;
    eval.want_gpu_claim = false;
    return eval;
}

static void ExpectFlagsStayFalse(const modelnet::SwarmCpuEvalResult& result)
{
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.gpu_claimed);
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_eval)
{
    modelnet::SwarmCpuEval eval = NotedEval();
    eval.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmCpuEvalResult result = modelnet::SwarmNoteCpuEval(eval, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(empty_node_id_wins_over_gpu_claim_and_publish)
{
    modelnet::SwarmCpuEval eval = NotedEval();
    eval.node_id.clear();
    eval.cpu_available = true;
    eval.want_publish_rate = true;
    eval.want_gpu_claim = true;
    std::string err = "prior";
    const modelnet::SwarmCpuEvalResult result = modelnet::SwarmNoteCpuEval(eval, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(want_gpu_claim_is_no_gpu)
{
    modelnet::SwarmCpuEval eval = NotedEval();
    eval.want_gpu_claim = true;
    std::string err = "prior";
    const modelnet::SwarmCpuEvalResult result = modelnet::SwarmNoteCpuEval(eval, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NO_GPU");
    BOOST_CHECK_EQUAL(err, "NO_GPU");
}

BOOST_AUTO_TEST_CASE(want_gpu_claim_wins_when_cpu_available_and_want_publish_rate)
{
    modelnet::SwarmCpuEval eval = NotedEval();
    eval.cpu_available = true;
    eval.want_publish_rate = true;
    eval.want_gpu_claim = true;
    std::string err = "prior";
    const modelnet::SwarmCpuEvalResult result = modelnet::SwarmNoteCpuEval(eval, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK(eval.cpu_available);
    BOOST_CHECK(eval.want_publish_rate);
    BOOST_CHECK(eval.want_gpu_claim);
    BOOST_CHECK_EQUAL(result.code, "NO_GPU");
    BOOST_CHECK_EQUAL(err, "NO_GPU");
}

BOOST_AUTO_TEST_CASE(cpu_unavailable_is_absent)
{
    modelnet::SwarmCpuEval eval = NotedEval();
    eval.cpu_available = false;
    eval.want_publish_rate = false;
    eval.want_gpu_claim = false;
    std::string err = "prior";
    const modelnet::SwarmCpuEvalResult result = modelnet::SwarmNoteCpuEval(eval, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK(!eval.cpu_available);
    BOOST_CHECK_EQUAL(result.code, "ABSENT");
    BOOST_CHECK_EQUAL(err, "ABSENT");
}

BOOST_AUTO_TEST_CASE(cpu_unavailable_wins_over_want_publish_rate)
{
    modelnet::SwarmCpuEval eval = NotedEval();
    eval.cpu_available = false;
    eval.want_publish_rate = true;
    eval.want_gpu_claim = false;
    std::string err = "prior";
    const modelnet::SwarmCpuEvalResult result = modelnet::SwarmNoteCpuEval(eval, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "ABSENT");
    BOOST_CHECK_EQUAL(err, "ABSENT");
}

BOOST_AUTO_TEST_CASE(want_publish_rate_is_unmeasured)
{
    modelnet::SwarmCpuEval eval = NotedEval();
    eval.cpu_available = true;
    eval.want_publish_rate = true;
    eval.want_gpu_claim = false;
    std::string err = "prior";
    const modelnet::SwarmCpuEvalResult result = modelnet::SwarmNoteCpuEval(eval, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(cpu_available_without_wants_is_noted)
{
    modelnet::SwarmCpuEval eval = NotedEval();
    eval.cpu_available = true;
    eval.want_publish_rate = false;
    eval.want_gpu_claim = false;
    std::string err = "prior";
    const modelnet::SwarmCpuEvalResult result = modelnet::SwarmNoteCpuEval(eval, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK(eval.cpu_available);
    BOOST_CHECK(!eval.want_publish_rate);
    BOOST_CHECK(!eval.want_gpu_claim);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
