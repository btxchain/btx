// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_benchrec.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_benchrec_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_is_bench)
{
    modelnet::SwarmBenchRec bench;
    bench.bench_id = "";
    bench.engine_name = "engine";
    bench.model_name = "model";
    bench.hardware_present = true;
    bench.measurement_finite = true;
    std::string err;
    const modelnet::SwarmBenchRecResult result = modelnet::SwarmRecordBenchmark(bench, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens, 0);
    BOOST_CHECK_EQUAL(result.code, "BENCH");
    BOOST_CHECK_EQUAL(err, "BENCH");
}

BOOST_AUTO_TEST_CASE(empty_engine_is_engine)
{
    modelnet::SwarmBenchRec bench;
    bench.bench_id = "bench";
    bench.engine_name = "";
    bench.model_name = "model";
    bench.hardware_present = true;
    bench.measurement_finite = true;
    std::string err;
    const modelnet::SwarmBenchRecResult result = modelnet::SwarmRecordBenchmark(bench, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens, 0);
    BOOST_CHECK_EQUAL(result.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
}

BOOST_AUTO_TEST_CASE(hardware_absent_is_unqualified)
{
    modelnet::SwarmBenchRec bench;
    bench.bench_id = "bench";
    bench.engine_name = "engine";
    bench.model_name = "model";
    bench.hardware_present = false;
    bench.measurement_finite = true;
    std::string err;
    const modelnet::SwarmBenchRecResult result = modelnet::SwarmRecordBenchmark(bench, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens, 0);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(non_finite_measurement_is_unmeasured)
{
    modelnet::SwarmBenchRec bench;
    bench.bench_id = "bench";
    bench.engine_name = "engine";
    bench.model_name = "model";
    bench.hardware_present = true;
    bench.measurement_finite = false;
    std::string err;
    const modelnet::SwarmBenchRecResult result = modelnet::SwarmRecordBenchmark(bench, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(reported_tokens_is_range)
{
    modelnet::SwarmBenchRec bench;
    bench.bench_id = "bench";
    bench.engine_name = "engine";
    bench.model_name = "model";
    bench.hardware_present = true;
    bench.ablation = true;
    bench.measurement_finite = true;
    bench.reported_tokens = 4;
    bench.want_publish = false;
    std::string err;
    const modelnet::SwarmBenchRecResult result = modelnet::SwarmRecordBenchmark(bench, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens, 0);
    BOOST_CHECK_EQUAL(result.code, "RANGE");
    BOOST_CHECK_EQUAL(err, "RANGE");
}

BOOST_AUTO_TEST_CASE(noted_keeps_ablation)
{
    modelnet::SwarmBenchRec bench;
    bench.bench_id = "bench";
    bench.engine_name = "engine";
    bench.model_name = "model";
    bench.hardware_present = true;
    bench.ablation = true;
    bench.measurement_finite = true;
    bench.reported_tokens = 0;
    bench.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmBenchRecResult result = modelnet::SwarmRecordBenchmark(bench, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(result.ablation);
}

BOOST_AUTO_TEST_SUITE_END()
