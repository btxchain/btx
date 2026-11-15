// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workerdrop.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_workerdrop_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_task_id_or_worker_id_is_worker)
{
    std::string err = "prior";
    modelnet::SwarmWorkerDropRequest missing_task;
    missing_task.worker_id = "worker-a";
    missing_task.result_stored = false;
    missing_task.worker_connected = false;
    const modelnet::SwarmWorkerDropResult no_task = modelnet::SwarmNoteWorkerDrop(missing_task, err);
    BOOST_CHECK(!no_task.executed);
    BOOST_CHECK(!no_task.result_kept);
    BOOST_CHECK_EQUAL(no_task.code, "WORKER");
    BOOST_CHECK_EQUAL(err, "WORKER");

    modelnet::SwarmWorkerDropRequest missing_worker;
    missing_worker.task_id = "task-a";
    missing_worker.result_stored = true;
    missing_worker.worker_connected = true;
    const modelnet::SwarmWorkerDropResult no_worker = modelnet::SwarmNoteWorkerDrop(missing_worker, err);
    BOOST_CHECK(!no_worker.executed);
    BOOST_CHECK(!no_worker.result_kept);
    BOOST_CHECK_EQUAL(no_worker.code, "WORKER");
    BOOST_CHECK_EQUAL(err, "WORKER");

    modelnet::SwarmWorkerDropRequest both_empty;
    both_empty.result_stored = true;
    both_empty.worker_connected = false;
    const modelnet::SwarmWorkerDropResult empty = modelnet::SwarmNoteWorkerDrop(both_empty, err);
    BOOST_CHECK(!empty.executed);
    BOOST_CHECK(!empty.result_kept);
    BOOST_CHECK_EQUAL(empty.code, "WORKER");
    BOOST_CHECK_EQUAL(err, "WORKER");
}

BOOST_AUTO_TEST_CASE(absent_result_wins_when_worker_is_disconnected)
{
    std::string err = "prior";
    modelnet::SwarmWorkerDropRequest request;
    request.task_id = "task-a";
    request.worker_id = "worker-a";
    request.result_stored = false;
    request.worker_connected = false;
    const modelnet::SwarmWorkerDropResult disconnected = modelnet::SwarmNoteWorkerDrop(request, err);
    BOOST_CHECK(!disconnected.executed);
    BOOST_CHECK(!disconnected.result_kept);
    BOOST_CHECK_EQUAL(disconnected.code, "RESULT_ABSENT");
    BOOST_CHECK_EQUAL(err, "RESULT_ABSENT");

    request.worker_connected = true;
    const modelnet::SwarmWorkerDropResult connected = modelnet::SwarmNoteWorkerDrop(request, err);
    BOOST_CHECK(!connected.executed);
    BOOST_CHECK(!connected.result_kept);
    BOOST_CHECK_EQUAL(connected.code, "RESULT_ABSENT");
    BOOST_CHECK_EQUAL(err, "RESULT_ABSENT");
}

BOOST_AUTO_TEST_CASE(stored_result_is_kept_when_worker_drops)
{
    std::string err = "prior";
    modelnet::SwarmWorkerDropRequest request;
    request.task_id = "task-a";
    request.worker_id = "worker-a";
    request.result_stored = true;
    request.worker_connected = false;
    const modelnet::SwarmWorkerDropResult result = modelnet::SwarmNoteWorkerDrop(request, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(result.result_kept);
    BOOST_CHECK_EQUAL(result.code, "DROPPED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(noted_keeps_stored_result_and_does_not_execute)
{
    std::string err = "prior";
    modelnet::SwarmWorkerDropRequest request;
    request.task_id = "task-a";
    request.worker_id = "worker-a";
    request.result_stored = true;
    request.worker_connected = true;
    const modelnet::SwarmWorkerDropResult result = modelnet::SwarmNoteWorkerDrop(request, err);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(result.result_kept);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
