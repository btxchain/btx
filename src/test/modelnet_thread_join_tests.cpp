// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/thread_join.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

BOOST_FIXTURE_TEST_SUITE(modelnet_thread_join_tests, BasicTestingSetup)

namespace {
// Mirrors RetrieveJob: owns a worker thread and joins it unless the caller is
// that worker. The worker lambda holds the last shared_ptr, so when the lambda
// returns, this object is destroyed on the worker thread.
struct SelfJoiner {
    std::thread worker;
    ~SelfJoiner() { modelnet::JoinWorkerUnlessSelf(worker); }
};
} // namespace

BOOST_AUTO_TEST_CASE(job_destroyed_on_its_own_worker_does_not_deadlock)
{
    std::atomic<bool> go{false};
    auto job = std::make_shared<SelfJoiner>();
    std::weak_ptr<SelfJoiner> weak = job;
    job->worker = std::thread([job, &go]() mutable {
        while (!go.load()) std::this_thread::yield();
        // Drop this thread's own owning reference. With the external reference
        // already gone, the last reference falls here, on the worker thread,
        // so ~SelfJoiner runs on this thread. A plain join() would deadlock
        // (and terminate); JoinWorkerUnlessSelf detaches instead.
        job.reset();
    });
    // The external owner is released; only the lambda's reference remains.
    job.reset();
    go.store(true);
    for (int i = 0; i < 2000 && !weak.expired(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    BOOST_CHECK(weak.expired());
}

BOOST_AUTO_TEST_CASE(join_waits_for_a_worker_on_another_thread)
{
    // The ordinary path: the owner is on a different thread, so the worker is
    // joined and has finished when the object is destroyed.
    std::atomic<int> ran{0};
    {
        SelfJoiner job;
        job.worker = std::thread([&ran]() { ran.store(1); });
    }
    BOOST_CHECK_EQUAL(ran.load(), 1);
}

BOOST_AUTO_TEST_SUITE_END()
