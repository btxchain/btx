// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_infer/publish.h>
#include <modelnet/swarm_infer/runtime.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_infer_publish_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(publish_is_held_and_stores_no_rate)
{
    modelnet::SwarmInferRateHold hold;
    hold.published = true;
    hold.rate_stored = true;
    hold.tokens_per_sec = 80.0;
    std::string err = "prior";
    const std::string code = modelnet::SwarmInferHoldPublish(hold, err);
    BOOST_REQUIRE_EQUAL(code, "HELD");
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!hold.published);
    BOOST_REQUIRE(!hold.rate_stored);
    BOOST_REQUIRE_EQUAL(hold.tokens_per_sec, -1.0);
}

BOOST_AUTO_TEST_CASE(vllm_sglang_and_cuda_are_not_started)
{
    modelnet::SwarmInferRuntimeRequest request;
    request.want_vllm = true;
    request.want_sglang = true;
    request.want_cuda = true;
    std::string err = "prior";
    const modelnet::SwarmInferRuntime runtime = modelnet::SwarmInferConsiderRuntime(request, err);
    BOOST_REQUIRE(!runtime.started);
    BOOST_REQUIRE(!runtime.process_spawned);
    BOOST_REQUIRE_EQUAL(err, "NOT_STARTED");
}

BOOST_AUTO_TEST_SUITE_END()
