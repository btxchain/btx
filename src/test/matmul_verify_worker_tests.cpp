// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// WP-7 / C5: unit tests for the async ENC-DR verify worker
// (node::MatMulVerifyWorker) and the bounded ENC-DR verdict memo (pow.h).

#include <node/matmul_verify_worker.h>

#include <chainparams.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

using node::MatMulVerifyWorker;

namespace {

//! Busy-wait until pred() or the deadline; returns pred()'s final value.
template <typename Pred>
bool WaitFor(Pred pred, std::chrono::milliseconds timeout = std::chrono::milliseconds{20000})
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!pred()) {
        if (std::chrono::steady_clock::now() > deadline) return pred();
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    return true;
}

//! Latch the test controls: verify calls block on it until Release().
struct BlockingVerify {
    std::mutex mutex;
    std::condition_variable cv;
    bool released{false};
    std::atomic<int> running{0};
    std::atomic<int> max_running{0};
    std::atomic<int> total_calls{0};

    bool Run()
    {
        const int now_running{++running};
        int prev = max_running.load();
        while (prev < now_running && !max_running.compare_exchange_weak(prev, now_running)) {}
        ++total_calls;
        {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock, [this] { return released; });
        }
        --running;
        return true;
    }

    void Release()
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            released = true;
        }
        cv.notify_all();
    }
};

//! Sentinel standing in for the RAII pending-verification slot: counts
//! destructions, so we can prove queued-but-never-run jobs still release
//! their captured resources when Stop() drains the queue.
struct SlotSentinel {
    std::atomic<int>* released;
    explicit SlotSentinel(std::atomic<int>* r) : released{r} {}
    ~SlotSentinel() { ++*released; }
};

std::shared_ptr<const CBlock> MakeBlock(uint32_t salt)
{
    auto block{std::make_shared<CBlock>()};
    block->nNonce = salt; // distinct hashes per job
    return block;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_verify_worker_tests, BasicTestingSetup)

// Design test A.10 #1: never more than pool-size verifications run at once and
// completions all run exactly once.
BOOST_AUTO_TEST_CASE(bounded_concurrency)
{
    const Consensus::Params& params = Params().GetConsensus();
    BlockingVerify gate;
    std::atomic<int> completions{0};
    MatMulVerifyWorker worker{params, /*max_threads=*/2,
                              [&](const CBlock&, int32_t) { return gate.Run(); }};

    constexpr int kJobs{6};
    for (int i = 0; i < kJobs; ++i) {
        MatMulVerifyWorker::Job job{MakeBlock(i), /*height=*/100,
                                    [&](bool ok) {
                                        BOOST_CHECK(ok);
                                        ++completions;
                                    }};
        BOOST_CHECK(worker.Enqueue(job));
    }
    // Both worker threads park inside the gate; the rest stays queued.
    BOOST_CHECK(WaitFor([&] { return gate.running.load() == 2; }));
    BOOST_CHECK_EQUAL(worker.QueueDepthForTest(), kJobs - 2);
    BOOST_CHECK_EQUAL(completions.load(), 0);

    gate.Release();
    BOOST_CHECK(WaitFor([&] { return completions.load() == kJobs; }));
    BOOST_CHECK_EQUAL(gate.total_calls.load(), kJobs);
    // The pool size bound held throughout.
    BOOST_CHECK_LE(gate.max_running.load(), 2);
    BOOST_CHECK_EQUAL(worker.QueueDepthForTest(), 0U);
}

// Design test A.10 #3: Stop() with queued jobs runs NO queued completion, but
// every job's captured RAII state (the verification slot) is still released.
BOOST_AUTO_TEST_CASE(stop_drains_queue_without_completions)
{
    const Consensus::Params& params = Params().GetConsensus();
    BlockingVerify gate;
    std::atomic<int> completions{0};
    std::atomic<int> slots_released{0};
    MatMulVerifyWorker worker{params, /*max_threads=*/1,
                              [&](const CBlock&, int32_t) { return gate.Run(); }};

    constexpr int kJobs{4};
    for (int i = 0; i < kJobs; ++i) {
        auto sentinel{std::make_shared<SlotSentinel>(&slots_released)};
        MatMulVerifyWorker::Job job{MakeBlock(i), /*height=*/100,
                                    [&completions, sentinel](bool) { ++completions; }};
        BOOST_CHECK(worker.Enqueue(job));
    }
    BOOST_CHECK(WaitFor([&] { return gate.running.load() == 1; }));
    BOOST_CHECK_EQUAL(worker.QueueDepthForTest(), kJobs - 1);

    // Let the in-flight job finish while Stop() joins; queued jobs must be
    // destroyed without their completions running.
    gate.Release();
    worker.Stop();
    BOOST_CHECK_EQUAL(completions.load(), 1);       // only the in-flight job completed
    BOOST_CHECK_EQUAL(slots_released.load(), kJobs); // but every slot was released

    // Enqueue after Stop() fails and leaves the job intact for the caller's
    // synchronous fallback.
    MatMulVerifyWorker::Job late{MakeBlock(99), /*height=*/100, [&](bool) { ++completions; }};
    BOOST_CHECK(!worker.Enqueue(late));
    BOOST_CHECK(late.block != nullptr);
    BOOST_CHECK(late.completion);
    late.completion(false);
    BOOST_CHECK_EQUAL(completions.load(), 2);
}

// Design test A.10 #4: the ENC-DR verdict memo is bounded at 64 entries with
// FIFO eviction; lookups hit exactly the retained window.
BOOST_AUTO_TEST_CASE(encdr_verdict_memo_bounded_fifo)
{
    // Use a disjoint hash namespace so repeated test runs cannot collide.
    const auto salted_hash = [](uint32_t i) {
        uint256 h;
        h.data()[0] = 0xED;
        h.data()[1] = static_cast<uint8_t>(i);
        h.data()[2] = static_cast<uint8_t>(i >> 8);
        h.data()[3] = 0x77;
        return h;
    };

    constexpr uint32_t kInserted{100};
    constexpr uint32_t kCap{64};
    for (uint32_t i = 0; i < kInserted; ++i) {
        CacheMatMulEncDrVerdict(salted_hash(i), /*valid=*/(i % 3) == 0);
    }
    // The oldest kInserted-kCap entries were FIFO-evicted...
    for (uint32_t i = 0; i < kInserted - kCap; ++i) {
        BOOST_CHECK(!LookupMatMulEncDrVerdict(salted_hash(i)).has_value());
    }
    // ...and the newest kCap entries are retained with the right verdicts.
    for (uint32_t i = kInserted - kCap; i < kInserted; ++i) {
        const auto memo{LookupMatMulEncDrVerdict(salted_hash(i))};
        BOOST_REQUIRE(memo.has_value());
        BOOST_CHECK_EQUAL(*memo, (i % 3) == 0);
    }
    // Re-caching an existing key keeps its (pure-function) verdict readable.
    CacheMatMulEncDrVerdict(salted_hash(kInserted - 1), (kInserted - 1) % 3 == 0);
    BOOST_CHECK(LookupMatMulEncDrVerdict(salted_hash(kInserted - 1)).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
