// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandbox_plan.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_sandbox_plan_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_is_sandbox)
{
    modelnet::SwarmSandboxRequest request;
    request.sandbox_id.clear();
    request.requested_threads = 4;
    request.requested_mib = 512;
    std::string err = "prior";
    const modelnet::SwarmSandboxPlan plan = modelnet::SwarmPlanSandbox(request, err);
    BOOST_CHECK(!plan.admitted);
    BOOST_CHECK(!plan.launched);
    BOOST_CHECK(!plan.network_allowed);
    BOOST_CHECK_EQUAL(plan.threads, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(plan.memory_mib, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(plan.code, "SANDBOX");
    BOOST_CHECK_EQUAL(err, "SANDBOX");
}

BOOST_AUTO_TEST_CASE(host_interpreter_is_host)
{
    modelnet::SwarmSandboxRequest request;
    request.sandbox_id = "box-1";
    request.host_interpreter = true;
    request.want_launch = false;
    request.requested_threads = 4;
    request.requested_mib = 512;
    std::string err = "prior";
    const modelnet::SwarmSandboxPlan plan = modelnet::SwarmPlanSandbox(request, err);
    BOOST_CHECK(!plan.admitted);
    BOOST_CHECK(!plan.launched);
    BOOST_CHECK(!plan.network_allowed);
    BOOST_CHECK_EQUAL(plan.threads, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(plan.memory_mib, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(plan.code, "HOST");
    BOOST_CHECK_EQUAL(err, "HOST");
}

BOOST_AUTO_TEST_CASE(over_cap_threads_and_memory_is_capped)
{
    modelnet::SwarmSandboxRequest request;
    request.sandbox_id = "box-1";
    request.requested_threads = 128;
    request.requested_mib = 32768;
    request.host_interpreter = false;
    request.want_launch = false;
    std::string err = "prior";
    const modelnet::SwarmSandboxPlan plan = modelnet::SwarmPlanSandbox(request, err);
    BOOST_CHECK(!plan.admitted);
    BOOST_CHECK(!plan.launched);
    BOOST_CHECK(!plan.network_allowed);
    BOOST_CHECK_EQUAL(plan.threads, static_cast<int64_t>(64));
    BOOST_CHECK_EQUAL(plan.memory_mib, static_cast<int64_t>(16384));
    BOOST_CHECK_EQUAL(plan.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_launch_is_held)
{
    modelnet::SwarmSandboxRequest request;
    request.sandbox_id = "box-1";
    request.requested_threads = 4;
    request.requested_mib = 512;
    request.want_launch = true;
    request.network = true;
    std::string err = "prior";
    const modelnet::SwarmSandboxPlan plan = modelnet::SwarmPlanSandbox(request, err);
    BOOST_CHECK(plan.admitted);
    BOOST_CHECK(!plan.launched);
    BOOST_CHECK(!plan.network_allowed);
    BOOST_CHECK_EQUAL(plan.threads, static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(plan.memory_mib, static_cast<int64_t>(512));
    BOOST_CHECK_EQUAL(plan.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_request_is_noted)
{
    modelnet::SwarmSandboxRequest request;
    request.sandbox_id = "box-1";
    request.requested_threads = 4;
    request.requested_mib = 512;
    request.want_launch = false;
    request.host_interpreter = false;
    std::string err = "prior";
    const modelnet::SwarmSandboxPlan plan = modelnet::SwarmPlanSandbox(request, err);
    BOOST_CHECK(plan.admitted);
    BOOST_CHECK(!plan.launched);
    BOOST_CHECK(!plan.network_allowed);
    BOOST_CHECK_EQUAL(plan.threads, static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(plan.memory_mib, static_cast<int64_t>(512));
    BOOST_CHECK_EQUAL(plan.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
