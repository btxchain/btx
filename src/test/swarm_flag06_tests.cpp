// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag06.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flag06_tests, BasicTestingSetup)

static modelnet::SwarmFlag06 NotedTrain()
{
    modelnet::SwarmFlag06 in;
    in.worker_a = "worker-a";
    in.worker_b = "worker-b";
    in.checkpoint_saved = true;
    in.want_pair = false;
    in.want_pass = false;
    return in;
}

static void ExpectAlwaysFalse(const modelnet::SwarmFlag06Result& result)
{
    BOOST_CHECK_EQUAL(result.paired, false);
    BOOST_CHECK_EQUAL(result.distributed, false);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
}

BOOST_AUTO_TEST_CASE(empty_worker_a_is_worker)
{
    modelnet::SwarmFlag06 in = NotedTrain();
    in.worker_a.clear();
    in.want_pair = true;
    in.checkpoint_saved = false;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag06Result result = modelnet::SwarmStageTrain(in, err);
    ExpectAlwaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "WORKER");
    BOOST_CHECK_EQUAL(err, "WORKER");
}

BOOST_AUTO_TEST_CASE(empty_worker_b_is_worker)
{
    modelnet::SwarmFlag06 in = NotedTrain();
    in.worker_b.clear();
    in.want_pair = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag06Result result = modelnet::SwarmStageTrain(in, err);
    ExpectAlwaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "WORKER");
    BOOST_CHECK_EQUAL(err, "WORKER");
}

BOOST_AUTO_TEST_CASE(empty_workers_win_over_later_flags)
{
    modelnet::SwarmFlag06 in;
    in.worker_a.clear();
    in.worker_b.clear();
    in.checkpoint_saved = false;
    in.want_pair = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag06Result result = modelnet::SwarmStageTrain(in, err);
    ExpectAlwaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "WORKER");
    BOOST_CHECK_EQUAL(err, "WORKER");
}

BOOST_AUTO_TEST_CASE(same_worker_is_same_worker)
{
    modelnet::SwarmFlag06 in = NotedTrain();
    in.worker_b = in.worker_a;
    std::string err = "prior";
    const modelnet::SwarmFlag06Result result = modelnet::SwarmStageTrain(in, err);
    ExpectAlwaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "SAME_WORKER");
    BOOST_CHECK_EQUAL(result.paired, false);
    BOOST_CHECK_EQUAL(err, "SAME_WORKER");
}

BOOST_AUTO_TEST_CASE(same_worker_wins_over_later_flags)
{
    modelnet::SwarmFlag06 in = NotedTrain();
    in.worker_a = "same";
    in.worker_b = "same";
    in.checkpoint_saved = false;
    in.want_pair = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag06Result result = modelnet::SwarmStageTrain(in, err);
    ExpectAlwaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "SAME_WORKER");
    BOOST_CHECK_EQUAL(result.paired, false);
    BOOST_CHECK_EQUAL(err, "SAME_WORKER");
}

BOOST_AUTO_TEST_CASE(want_pair_is_out_of_scope)
{
    modelnet::SwarmFlag06 in = NotedTrain();
    in.want_pair = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag06Result result = modelnet::SwarmStageTrain(in, err);
    ExpectAlwaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "OUT_OF_SCOPE");
    BOOST_CHECK_EQUAL(result.paired, false);
    BOOST_CHECK_EQUAL(err, "OUT_OF_SCOPE");
}

BOOST_AUTO_TEST_CASE(want_pair_wins_over_checkpoint_and_pass)
{
    modelnet::SwarmFlag06 in = NotedTrain();
    in.want_pair = true;
    in.checkpoint_saved = false;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag06Result result = modelnet::SwarmStageTrain(in, err);
    ExpectAlwaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "OUT_OF_SCOPE");
    BOOST_CHECK_EQUAL(result.paired, false);
    BOOST_CHECK_EQUAL(err, "OUT_OF_SCOPE");
}

BOOST_AUTO_TEST_CASE(missing_checkpoint_is_no_checkpoint)
{
    modelnet::SwarmFlag06 in = NotedTrain();
    in.checkpoint_saved = false;
    in.want_pair = false;
    in.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmFlag06Result result = modelnet::SwarmStageTrain(in, err);
    ExpectAlwaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NO_CHECKPOINT");
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(err, "NO_CHECKPOINT");
}

BOOST_AUTO_TEST_CASE(missing_checkpoint_wins_over_want_pass)
{
    modelnet::SwarmFlag06 in = NotedTrain();
    in.checkpoint_saved = false;
    in.want_pair = false;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag06Result result = modelnet::SwarmStageTrain(in, err);
    ExpectAlwaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NO_CHECKPOINT");
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(err, "NO_CHECKPOINT");
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmFlag06 in = NotedTrain();
    in.want_pair = false;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag06Result result = modelnet::SwarmStageTrain(in, err);
    ExpectAlwaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(distinct_workers_are_noted)
{
    modelnet::SwarmFlag06 in = NotedTrain();
    std::string err = "prior";
    const modelnet::SwarmFlag06Result result = modelnet::SwarmStageTrain(in, err);
    ExpectAlwaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK_EQUAL(result.paired, false);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
