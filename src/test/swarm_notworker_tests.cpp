// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notworker.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notworker_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_worker_id)
{
    modelnet::SwarmNotWorker note;
    std::string err = "stale";
    const modelnet::SwarmNotWorkerResult result = modelnet::SwarmNoteNotWorker(note, err);
    BOOST_CHECK_EQUAL(result.code, "WORKER");
    BOOST_CHECK_EQUAL(err, "WORKER");
    BOOST_CHECK(!result.dropped);
}

BOOST_AUTO_TEST_CASE(want_drop_is_not_injected)
{
    modelnet::SwarmNotWorker note;
    note.worker_id = "worker-1";
    note.want_drop = true;
    std::string err = "stale";
    const modelnet::SwarmNotWorkerResult result = modelnet::SwarmNoteNotWorker(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_INJECTED");
    BOOST_CHECK_EQUAL(err, "NOT_INJECTED");
    BOOST_CHECK(!result.dropped);
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotWorker note;
    note.worker_id = "worker-1";
    std::string err = "stale";
    const modelnet::SwarmNotWorkerResult result = modelnet::SwarmNoteNotWorker(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.dropped);
}

BOOST_AUTO_TEST_SUITE_END()
