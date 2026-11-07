// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_runtimepick.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_runtimepick_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_name_is_runtime)
{
    modelnet::SwarmRuntimePickRequest request;
    request.name = "";
    request.installed = true;
    request.measurement_taken = true;
    std::string err = "prior";
    const modelnet::SwarmRuntimePickResult result = modelnet::SwarmSelectRuntime(request, err);
    BOOST_CHECK(!result.selected);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "RUNTIME");
    BOOST_CHECK_EQUAL(err, "RUNTIME");
}

BOOST_AUTO_TEST_CASE(unknown_name_is_runtime)
{
    modelnet::SwarmRuntimePickRequest request;
    request.name = "VLLM";
    request.installed = true;
    request.measurement_taken = true;
    std::string err = "prior";
    const modelnet::SwarmRuntimePickResult result = modelnet::SwarmSelectRuntime(request, err);
    BOOST_CHECK(!result.selected);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "RUNTIME");
    BOOST_CHECK_EQUAL(err, "RUNTIME");
}

BOOST_AUTO_TEST_CASE(missing_vllm_is_engine_absent)
{
    modelnet::SwarmRuntimePickRequest request;
    request.name = "vllm";
    request.installed = false;
    request.measurement_taken = true;
    std::string err = "prior";
    const modelnet::SwarmRuntimePickResult result = modelnet::SwarmSelectRuntime(request, err);
    BOOST_CHECK(!result.selected);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(installed_unmeasured_sglang_is_local_candidate)
{
    modelnet::SwarmRuntimePickRequest request;
    request.name = "sglang";
    request.installed = true;
    request.measurement_taken = false;
    std::string err = "prior";
    const modelnet::SwarmRuntimePickResult result = modelnet::SwarmSelectRuntime(request, err);
    BOOST_CHECK(result.selected);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "INSTALLED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(measured_torch_is_selected)
{
    modelnet::SwarmRuntimePickRequest request;
    request.name = "torch";
    request.installed = true;
    request.measurement_taken = true;
    std::string err = "prior";
    const modelnet::SwarmRuntimePickResult result = modelnet::SwarmSelectRuntime(request, err);
    BOOST_CHECK(result.selected);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "SELECTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
