// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capassign.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_capassign_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(missing_capability_assigns_nobody)
{
    modelnet::SwarmCapAssign assign;
    std::string err = "prior";
    BOOST_CHECK(!assign.AddWorker("", {"build"}, err));
    BOOST_CHECK_EQUAL(err, "WORKER");
    BOOST_REQUIRE(assign.AddWorker("w1", {"build"}, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!assign.AddWorker("w1", {"gpu"}, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(assign.AddWorker("w-empty", {}, err));

    std::string worker_out = "sentinel";
    BOOST_CHECK(!assign.Assign("job", "gpu", worker_out, err));
    BOOST_CHECK_EQUAL(err, "NOT_ACTED");
    BOOST_CHECK(worker_out.empty());
    BOOST_CHECK(assign.WorkerFor("job").empty());

    worker_out = "sentinel";
    BOOST_CHECK(!assign.Assign("", "gpu", worker_out, err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_CHECK_EQUAL(worker_out, "sentinel");
    BOOST_CHECK(!assign.Assign("job", "", worker_out, err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_CHECK(assign.WorkerFor("job").empty());

    // The refused assign stored nothing, and the replayed add did not gain gpu.
    BOOST_REQUIRE(assign.AddWorker("w2", {"gpu"}, err));
    BOOST_REQUIRE(assign.Assign("job", "gpu", worker_out, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(worker_out, "w2");
    BOOST_CHECK_EQUAL(assign.WorkerFor("job"), "w2");
}

BOOST_AUTO_TEST_CASE(earliest_matching_worker)
{
    modelnet::SwarmCapAssign assign;
    std::string err = "prior";
    BOOST_REQUIRE(assign.AddWorker("first", {"lint"}, err));
    BOOST_REQUIRE(assign.AddWorker("second", {"build", "test"}, err));
    BOOST_REQUIRE(assign.AddWorker("third", {"build", "lint"}, err));

    std::string worker_out = "sentinel";
    BOOST_REQUIRE(assign.Assign("pack", "build", worker_out, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(worker_out, "second");
    BOOST_CHECK_EQUAL(assign.WorkerFor("pack"), "second");

    BOOST_REQUIRE(assign.Assign("check", "lint", worker_out, err));
    BOOST_CHECK_EQUAL(worker_out, "first");
    BOOST_CHECK_EQUAL(assign.WorkerFor("check"), "first");

    BOOST_REQUIRE(assign.Assign("again", "build", worker_out, err));
    BOOST_CHECK_EQUAL(worker_out, "second");
    BOOST_CHECK_EQUAL(assign.WorkerFor("again"), "second");
    BOOST_CHECK_EQUAL(assign.WorkerFor("pack"), "second");
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_worker)
{
    modelnet::SwarmCapAssign assign;
    std::string err = "prior";
    BOOST_REQUIRE(assign.AddWorker("early", {"run"}, err));
    BOOST_REQUIRE(assign.AddWorker("late", {"run", "extra"}, err));

    std::string worker_out;
    BOOST_REQUIRE(assign.Assign("task", "run", worker_out, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(worker_out, "early");

    worker_out = "late";
    BOOST_CHECK(!assign.Assign("task", "run", worker_out, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(worker_out, "early");
    BOOST_CHECK_EQUAL(assign.WorkerFor("task"), "early");

    BOOST_CHECK(!assign.Assign("task", "extra", worker_out, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(worker_out, "early");
    BOOST_CHECK_EQUAL(assign.WorkerFor("task"), "early");

    BOOST_REQUIRE(assign.Assign("other", "extra", worker_out, err));
    BOOST_CHECK_EQUAL(worker_out, "late");
    BOOST_CHECK_EQUAL(assign.WorkerFor("other"), "late");
    BOOST_CHECK_EQUAL(assign.WorkerFor("task"), "early");
}

BOOST_AUTO_TEST_SUITE_END()
