// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag03.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flag03_tests, BasicTestingSetup)

static void CheckNeverMoved(const modelnet::SwarmFlag03Result& result)
{
    BOOST_CHECK_EQUAL(result.ran, false);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.broadcast, false);
}

BOOST_AUTO_TEST_CASE(empty_task_a_is_task)
{
    modelnet::SwarmFlag03 in;
    in.task_b = "task-b";
    in.leader_id = "leader-1";
    in.durable = true;
    in.want_run = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag03Result result = modelnet::SwarmStageCoordinate(in, err);
    BOOST_CHECK_EQUAL(result.code, "TASK");
    BOOST_CHECK_EQUAL(result.persisted, false);
    CheckNeverMoved(result);
    BOOST_CHECK_EQUAL(err, "TASK");
}

BOOST_AUTO_TEST_CASE(empty_task_b_is_task)
{
    modelnet::SwarmFlag03 in;
    in.task_a = "task-a";
    in.leader_id = "leader-1";
    in.durable = true;
    in.want_run = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag03Result result = modelnet::SwarmStageCoordinate(in, err);
    BOOST_CHECK_EQUAL(result.code, "TASK");
    BOOST_CHECK_EQUAL(result.persisted, false);
    CheckNeverMoved(result);
    BOOST_CHECK_EQUAL(err, "TASK");
}

BOOST_AUTO_TEST_CASE(empty_leader_id_is_task)
{
    modelnet::SwarmFlag03 in;
    in.task_a = "task-a";
    in.task_b = "task-b";
    in.durable = true;
    in.want_run = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag03Result result = modelnet::SwarmStageCoordinate(in, err);
    BOOST_CHECK_EQUAL(result.code, "TASK");
    BOOST_CHECK_EQUAL(result.persisted, false);
    CheckNeverMoved(result);
    BOOST_CHECK_EQUAL(err, "TASK");
}

BOOST_AUTO_TEST_CASE(same_task_is_same_task)
{
    modelnet::SwarmFlag03 in;
    in.task_a = "task-a";
    in.task_b = "task-a";
    in.leader_id = "leader-1";
    in.durable = true;
    in.want_run = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag03Result result = modelnet::SwarmStageCoordinate(in, err);
    BOOST_CHECK_EQUAL(result.code, "SAME_TASK");
    BOOST_CHECK_EQUAL(result.persisted, false);
    BOOST_CHECK_EQUAL(result.ran, false);
    CheckNeverMoved(result);
    BOOST_CHECK_EQUAL(err, "SAME_TASK");
}

BOOST_AUTO_TEST_CASE(want_run_is_not_run)
{
    modelnet::SwarmFlag03 in;
    in.task_a = "task-a";
    in.task_b = "task-b";
    in.leader_id = "leader-1";
    in.durable = true;
    in.want_run = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag03Result result = modelnet::SwarmStageCoordinate(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK_EQUAL(result.persisted, false);
    BOOST_CHECK_EQUAL(result.ran, false);
    CheckNeverMoved(result);
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmFlag03 in;
    in.task_a = "task-a";
    in.task_b = "task-b";
    in.leader_id = "leader-1";
    in.durable = true;
    in.want_run = false;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag03Result result = modelnet::SwarmStageCoordinate(in, err);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(result.persisted, false);
    BOOST_CHECK_EQUAL(result.passed, false);
    CheckNeverMoved(result);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(not_durable_is_lost)
{
    modelnet::SwarmFlag03 in;
    in.task_a = "task-a";
    in.task_b = "task-b";
    in.leader_id = "leader-1";
    in.durable = false;
    in.want_run = false;
    in.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmFlag03Result result = modelnet::SwarmStageCoordinate(in, err);
    BOOST_CHECK_EQUAL(result.code, "LOST");
    BOOST_CHECK_EQUAL(result.persisted, false);
    CheckNeverMoved(result);
    BOOST_CHECK_EQUAL(err, "LOST");
}

BOOST_AUTO_TEST_CASE(durable_distinct_tasks_are_persisted)
{
    modelnet::SwarmFlag03 in;
    in.task_a = "task-a";
    in.task_b = "task-b";
    in.leader_id = "leader-1";
    in.durable = true;
    in.want_run = false;
    in.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmFlag03Result result = modelnet::SwarmStageCoordinate(in, err);
    BOOST_CHECK_EQUAL(result.code, "PERSISTED");
    BOOST_CHECK_EQUAL(result.persisted, true);
    BOOST_CHECK_EQUAL(result.ran, false);
    BOOST_CHECK_EQUAL(result.passed, false);
    CheckNeverMoved(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
