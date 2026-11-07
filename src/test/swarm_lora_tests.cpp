// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_lora.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_lora_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(approximate_with_all_same_is_refused)
{
    std::string err = "prior";
    modelnet::SwarmKvReuseRequest request;
    request.same_weights = true;
    request.same_tokenizer = true;
    request.same_quantization = true;
    request.same_adapter = true;
    request.approximate_requested = true;
    const modelnet::SwarmKvReuseResult result = modelnet::SwarmAdmitKvReuse(request, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.exact);
    BOOST_CHECK_EQUAL(result.code, "APPROXIMATE");
    BOOST_CHECK_EQUAL(err, "APPROXIMATE");
}

BOOST_AUTO_TEST_CASE(quantization_mismatch_is_incompatible)
{
    std::string err = "prior";
    modelnet::SwarmKvReuseRequest request;
    request.same_weights = true;
    request.same_tokenizer = true;
    request.same_quantization = false;
    request.same_adapter = true;
    request.approximate_requested = false;
    const modelnet::SwarmKvReuseResult result = modelnet::SwarmAdmitKvReuse(request, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.exact);
    BOOST_CHECK_EQUAL(result.code, "INCOMPATIBLE");
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
}

BOOST_AUTO_TEST_CASE(exact_page_match_is_admitted)
{
    std::string err = "prior";
    modelnet::SwarmKvReuseRequest request;
    request.same_weights = true;
    request.same_tokenizer = true;
    request.same_quantization = true;
    request.same_adapter = true;
    request.approximate_requested = false;
    const modelnet::SwarmKvReuseResult result = modelnet::SwarmAdmitKvReuse(request, err);
    BOOST_CHECK(result.admitted);
    BOOST_CHECK(result.exact);
    BOOST_CHECK_EQUAL(result.code, "EXACT");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
