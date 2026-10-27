// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_engadapter.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_engadapter_tests, BasicTestingSetup)

static modelnet::SwarmEngAdapter NamedAdapter()
{
    modelnet::SwarmEngAdapter adapter;
    adapter.transfer_id = "transfer-1";
    adapter.engine_name = "engine-1";
    adapter.installed = true;
    adapter.cuda_ops = true;
    adapter.want_move = false;
    adapter.bytes = 64;
    return adapter;
}

BOOST_AUTO_TEST_CASE(empty_transfer_is_transfer)
{
    modelnet::SwarmEngAdapter adapter = NamedAdapter();
    adapter.transfer_id.clear();
    std::string err = "prior";
    const modelnet::SwarmEngAdapterResult result = modelnet::SwarmAdaptEngine(adapter, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "TRANSFER");
    BOOST_CHECK_EQUAL(err, "TRANSFER");
}

BOOST_AUTO_TEST_CASE(empty_engine_is_engine)
{
    modelnet::SwarmEngAdapter adapter = NamedAdapter();
    adapter.engine_name.clear();
    std::string err = "prior";
    const modelnet::SwarmEngAdapterResult result = modelnet::SwarmAdaptEngine(adapter, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
}

BOOST_AUTO_TEST_CASE(installed_false_is_engine_absent)
{
    modelnet::SwarmEngAdapter adapter = NamedAdapter();
    adapter.installed = false;
    adapter.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmEngAdapterResult result = modelnet::SwarmAdaptEngine(adapter, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(cuda_ops_false_is_engine_absent)
{
    modelnet::SwarmEngAdapter adapter = NamedAdapter();
    adapter.installed = true;
    adapter.cuda_ops = false;
    std::string err = "prior";
    const modelnet::SwarmEngAdapterResult result = modelnet::SwarmAdaptEngine(adapter, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(want_move_true_is_held)
{
    modelnet::SwarmEngAdapter adapter = NamedAdapter();
    adapter.installed = true;
    adapter.cuda_ops = true;
    adapter.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmEngAdapterResult result = modelnet::SwarmAdaptEngine(adapter, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_move_false_is_noted)
{
    modelnet::SwarmEngAdapter adapter = NamedAdapter();
    adapter.installed = true;
    adapter.cuda_ops = true;
    adapter.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmEngAdapterResult result = modelnet::SwarmAdaptEngine(adapter, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, static_cast<int64_t>(0));
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
