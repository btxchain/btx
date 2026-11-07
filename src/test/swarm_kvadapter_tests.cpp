// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvadapter.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_kvadapter_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_engine_is_engine)
{
    std::string err;
    modelnet::SwarmKvAdapterRequest request;
    request.engine = "";
    request.library_present = true;
    const modelnet::SwarmKvAdapterResult result = modelnet::SwarmTransferKv(request, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
}

BOOST_AUTO_TEST_CASE(absent_nixl_is_engine_absent)
{
    std::string err;
    modelnet::SwarmKvAdapterRequest request;
    request.engine = "nixl";
    request.library_present = false;
    const modelnet::SwarmKvAdapterResult result = modelnet::SwarmTransferKv(request, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(absent_mooncake_is_engine_absent)
{
    std::string err;
    modelnet::SwarmKvAdapterRequest request;
    request.engine = "mooncake";
    request.library_present = false;
    const modelnet::SwarmKvAdapterResult result = modelnet::SwarmTransferKv(request, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(absent_rdma_is_engine_absent)
{
    std::string err;
    modelnet::SwarmKvAdapterRequest request;
    request.engine = "rdma";
    request.library_present = false;
    const modelnet::SwarmKvAdapterResult result = modelnet::SwarmTransferKv(request, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(present_lmcache_is_local)
{
    std::string err = "prior";
    modelnet::SwarmKvAdapterRequest request;
    request.engine = "lmcache";
    request.library_present = true;
    const modelnet::SwarmKvAdapterResult result = modelnet::SwarmTransferKv(request, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "LOCAL");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(present_vllm_is_local)
{
    std::string err = "prior";
    modelnet::SwarmKvAdapterRequest request;
    request.engine = "vllm";
    request.library_present = true;
    const modelnet::SwarmKvAdapterResult result = modelnet::SwarmTransferKv(request, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "LOCAL");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
