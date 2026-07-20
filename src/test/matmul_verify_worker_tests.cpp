// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// WP-7 / C5: unit tests for the async ENC-DR verify worker
// (node::MatMulVerifyWorker) and the bounded ENC-DR verdict memo (pow.h).

#include <node/matmul_verify_worker.h>

#include <chainparams.h>
#include <consensus/params.h>
#include <matmul/matmul_v4_lt.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
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
                              [&](const CBlock&, int32_t, std::optional<int64_t>) { return gate.Run(); }};

    constexpr int kJobs{6};
    for (int i = 0; i < kJobs; ++i) {
        MatMulVerifyWorker::Job job{MakeBlock(i), /*height=*/100, /*parent_mtp=*/std::nullopt,
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
                              [&](const CBlock&, int32_t, std::optional<int64_t>) { return gate.Run(); }};

    constexpr int kJobs{4};
    for (int i = 0; i < kJobs; ++i) {
        auto sentinel{std::make_shared<SlotSentinel>(&slots_released)};
        MatMulVerifyWorker::Job job{MakeBlock(i), /*height=*/100, /*parent_mtp=*/std::nullopt,
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
    MatMulVerifyWorker::Job late{MakeBlock(99), /*height=*/100, /*parent_mtp=*/std::nullopt,
                                 [&](bool) { ++completions; }};
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

BOOST_AUTO_TEST_CASE(encdr_verdict_pin_survives_fifo_eviction_and_refcounts)
{
    const auto salted_hash = [](uint32_t i) {
        uint256 h;
        h.data()[0] = 0xA6;
        h.data()[1] = static_cast<uint8_t>(i);
        h.data()[2] = static_cast<uint8_t>(i >> 8);
        h.data()[3] = 0x5C;
        return h;
    };

    const uint256 pinned_hash{salted_hash(0)};
    CacheMatMulEncDrVerdict(pinned_hash, /*valid=*/true);
    const auto first_pin{PinCachedMatMulEncDrVerdict(pinned_hash)};
    const auto second_pin{PinCachedMatMulEncDrVerdict(pinned_hash)};
    BOOST_REQUIRE(first_pin.has_value());
    BOOST_REQUIRE(second_pin.has_value());
    BOOST_CHECK(*first_pin);
    BOOST_CHECK(*second_pin);

    // Evict the ordinary FIFO entry. The independent pin must remain visible
    // across admission -> validation, even while other workers finish enough
    // jobs to wrap the bounded memo.
    for (uint32_t i = 1; i <= 80; ++i) {
        CacheMatMulEncDrVerdict(salted_hash(i), /*valid=*/false);
    }
    auto memo{LookupMatMulEncDrVerdict(pinned_hash)};
    BOOST_REQUIRE(memo.has_value());
    BOOST_CHECK(*memo);

    // Nested owners release independently. Only the final unpin exposes that
    // the backing FIFO entry was evicted.
    UnpinMatMulEncDrVerdict(pinned_hash);
    memo = LookupMatMulEncDrVerdict(pinned_hash);
    BOOST_REQUIRE(memo.has_value());
    BOOST_CHECK(*memo);
    UnpinMatMulEncDrVerdict(pinned_hash);
    BOOST_CHECK(!LookupMatMulEncDrVerdict(pinned_hash).has_value());
}

// Phase B seal-as-PoW async path: parent MTP on the Job is forwarded into the
// verify seam (Classify/ProcessBlock supply it under cs_main; EncDr fails
// closed without it at seal heights).
BOOST_AUTO_TEST_CASE(seal_async_forwards_parent_mtp)
{
    const Consensus::Params& params = Params().GetConsensus();
    constexpr int64_t kMtp = 1'700'000'042;
    std::atomic<int> seen_mtp{0};
    std::atomic<int> seen_nullopt{0};
    std::atomic<int> completions{0};

    MatMulVerifyWorker worker{params, /*max_threads=*/1,
                              [&](const CBlock&, int32_t height, std::optional<int64_t> parent_mtp) {
                                  BOOST_CHECK_EQUAL(height, 42);
                                  if (parent_mtp.has_value() && *parent_mtp == kMtp) {
                                      ++seen_mtp;
                                      return true;
                                  }
                                  ++seen_nullopt;
                                  return false;
                              }};

    MatMulVerifyWorker::Job with_mtp{MakeBlock(1), /*height=*/42, kMtp,
                                     [&](bool ok) {
                                         BOOST_CHECK(ok);
                                         ++completions;
                                     }};
    BOOST_CHECK(worker.Enqueue(with_mtp));
    BOOST_CHECK(WaitFor([&] { return completions.load() == 1; }));
    BOOST_CHECK_EQUAL(seen_mtp.load(), 1);
    BOOST_CHECK_EQUAL(seen_nullopt.load(), 0);

    MatMulVerifyWorker::Job without_mtp{MakeBlock(2), /*height=*/42, std::nullopt,
                                        [&](bool ok) {
                                            BOOST_CHECK(!ok);
                                            ++completions;
                                        }};
    BOOST_CHECK(worker.Enqueue(without_mtp));
    BOOST_CHECK(WaitFor([&] { return completions.load() == 2; }));
    BOOST_CHECK_EQUAL(seen_nullopt.load(), 1);
}

// LT tip-verify pending / budget knobs height-select when DRLT is live.
BOOST_AUTO_TEST_CASE(lt_tip_verify_budget_knobs)
{
    Consensus::Params params;
    params.nMatMulMaxPendingVerifications = 16;
    params.nMatMulLTMaxPendingVerifications = 2;
    params.nMatMulV4Height = 1;
    params.nMatMulBMX4CHeight = 1; // IsDRLTActive requires IsBMX4CActive
    params.nMatMulDRLTHeight = 100;
    params.fMatMulLTSealAsPoW = false;
    params.nMatMulV4GlobalVerifyBudgetPerMin = 4;
    params.nMatMulV4PeerVerifyBudgetPerMin = 2;
    params.nMatMulLTGlobalVerifyBudgetPerMin = 1;
    params.nMatMulLTPeerVerifyBudgetPerMin = 1;
    params.nMatMulGlobalVerifyBudgetPerMin = 512;
    params.nMatMulPeerVerifyBudgetPerMin = 32;

    // Below DRLT: v4 (or v3) caps apply; LT knobs stay inert.
    BOOST_CHECK_EQUAL(EffectiveMatMulMaxPendingVerifications(params, /*reference_height=*/50), 16U);
    BOOST_CHECK_EQUAL(MatMulEncDrWorkUnits(params, 50), 1U);
    BOOST_CHECK_EQUAL(EffectiveMatMulGlobalVerifyBudgetPerMin(params, 50), 4U);
    BOOST_CHECK_EQUAL(EffectiveMatMulPeerVerifyBudgetPerMin(params, /*is_ibd=*/false, 50), 2U);
    BOOST_CHECK(CanStartMatMulVerification(15, params, 50));
    BOOST_CHECK(!CanStartMatMulVerification(16, params, 50));

    // At/above DRLT Phase A (seal off): LT tip-verify knobs apply; each job = 1 leaf unit.
    BOOST_CHECK_EQUAL(MatMulEncDrWorkUnits(params, 100), 1U);
    BOOST_CHECK_EQUAL(EffectiveMatMulMaxPendingVerifications(params, 100), 2U);
    BOOST_CHECK_EQUAL(EffectiveMatMulGlobalVerifyBudgetPerMin(params, 100), 1U);
    BOOST_CHECK_EQUAL(EffectiveMatMulPeerVerifyBudgetPerMin(params, /*is_ibd=*/false, 100), 1U);
    BOOST_CHECK(CanStartMatMulVerification(1, params, 100));
    BOOST_CHECK(!CanStartMatMulVerification(2, params, 100));

    // Phase B seal-as-PoW: each job costs Q* leaf units; pending cap = jobs *
    // Q*. The consensus parameter's default must agree with the canonical LT
    // default so one honest default seal fits every default one-job budget.
    params.fMatMulLTSealAsPoW = true;
    BOOST_CHECK_EQUAL(params.nMatMulConsensusQStar, matmul::v4::lt::kConsensusQStarDefault);
    BOOST_CHECK_EQUAL(MatMulEncDrWorkUnits(params, 100), 256U);
    BOOST_CHECK_EQUAL(EffectiveMatMulMaxPendingVerifications(params, 100), 512U);
    // The operator knobs are complete jobs/minute; effective admission is in
    // leaf work units. Default 1 must admit one honest Q*=256 seal job.
    BOOST_CHECK_EQUAL(EffectiveMatMulGlobalVerifyBudgetPerMin(params, 100), 256U);
    BOOST_CHECK_EQUAL(EffectiveMatMulPeerVerifyBudgetPerMin(
                          params, /*is_ibd=*/false, 100),
                      256U);
    BOOST_CHECK(CanStartMatMulVerification(/*pending=*/0, /*work_units=*/256, params, 100));
    BOOST_CHECK(CanStartMatMulVerification(/*pending=*/256, /*work_units=*/256, params, 100));
    BOOST_CHECK(!CanStartMatMulVerification(/*pending=*/257, /*work_units=*/256, params, 100));

    // The largest allowed Q* is accounted at its full weight as well.
    params.nMatMulConsensusQStar = 512;
    BOOST_CHECK_EQUAL(MatMulEncDrWorkUnits(params, 100), 512U);
    BOOST_CHECK_EQUAL(EffectiveMatMulMaxPendingVerifications(params, 100), 1024U);
    BOOST_CHECK_EQUAL(EffectiveMatMulGlobalVerifyBudgetPerMin(params, 100), 512U);
    BOOST_CHECK_EQUAL(EffectiveMatMulPeerVerifyBudgetPerMin(
                          params, /*is_ibd=*/false, 100),
                      512U);
    BOOST_CHECK(CanStartMatMulVerification(/*pending=*/0, /*work_units=*/512, params, 100));
    BOOST_CHECK(CanStartMatMulVerification(/*pending=*/512, /*work_units=*/512, params, 100));
    BOOST_CHECK(!CanStartMatMulVerification(/*pending=*/513, /*work_units=*/512, params, 100));

    // Invalid configuration values consistently fall back to the canonical
    // default for both job cost and every scaled admission budget.
    params.nMatMulConsensusQStar = 64;
    BOOST_CHECK_EQUAL(MatMulEncDrWorkUnits(params, 100), 256U);
    BOOST_CHECK_EQUAL(EffectiveMatMulMaxPendingVerifications(params, 100), 512U);
    BOOST_CHECK_EQUAL(EffectiveMatMulGlobalVerifyBudgetPerMin(params, 100), 256U);
    BOOST_CHECK_EQUAL(EffectiveMatMulPeerVerifyBudgetPerMin(
                          params, /*is_ibd=*/false, 100),
                      256U);
    BOOST_CHECK(CanStartMatMulVerification(/*pending=*/0, /*work_units=*/256, params, 100));

    // Large job counts saturate rather than wrapping during unit scaling. The
    // UINT32_MAX unbounded/test sentinel remains unbounded too.
    params.nMatMulConsensusQStar = 512;
    constexpr uint32_t overflowing_jobs{
        std::numeric_limits<uint32_t>::max() / 512U + 1U};
    params.nMatMulLTMaxPendingVerifications = overflowing_jobs;
    params.nMatMulLTGlobalVerifyBudgetPerMin = overflowing_jobs;
    params.nMatMulLTPeerVerifyBudgetPerMin = overflowing_jobs;
    BOOST_CHECK_EQUAL(EffectiveMatMulMaxPendingVerifications(params, 100),
                      std::numeric_limits<uint32_t>::max());
    BOOST_CHECK_EQUAL(EffectiveMatMulGlobalVerifyBudgetPerMin(params, 100),
                      std::numeric_limits<uint32_t>::max());
    BOOST_CHECK_EQUAL(EffectiveMatMulPeerVerifyBudgetPerMin(
                          params, /*is_ibd=*/false, 100),
                      std::numeric_limits<uint32_t>::max());
    BOOST_CHECK(CanStartMatMulVerification(
        std::numeric_limits<uint32_t>::max() - 512U, 512U, params, 100));
    BOOST_CHECK(!CanStartMatMulVerification(
        std::numeric_limits<uint32_t>::max() - 511U, 512U, params, 100));

    params.nMatMulLTMaxPendingVerifications = std::numeric_limits<uint32_t>::max();
    params.nMatMulLTGlobalVerifyBudgetPerMin = std::numeric_limits<uint32_t>::max();
    params.nMatMulLTPeerVerifyBudgetPerMin = std::numeric_limits<uint32_t>::max();
    BOOST_CHECK_EQUAL(EffectiveMatMulMaxPendingVerifications(params, 100),
                      std::numeric_limits<uint32_t>::max());
    BOOST_CHECK_EQUAL(EffectiveMatMulGlobalVerifyBudgetPerMin(params, 100),
                      std::numeric_limits<uint32_t>::max());
    BOOST_CHECK_EQUAL(EffectiveMatMulPeerVerifyBudgetPerMin(
                          params, /*is_ibd=*/false, 100),
                      std::numeric_limits<uint32_t>::max());
    BOOST_CHECK(CanStartMatMulVerification(
        std::numeric_limits<uint32_t>::max() - 512U, 512U, params, 100));
    BOOST_CHECK(!CanStartMatMulVerification(
        std::numeric_limits<uint32_t>::max() - 511U, 512U, params, 100));

    // DRLT disabled (INT32_MAX): LT knobs never select, even at high height.
    params.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    BOOST_CHECK_EQUAL(EffectiveMatMulMaxPendingVerifications(params, 1'000'000), 16U);
    BOOST_CHECK_EQUAL(EffectiveMatMulGlobalVerifyBudgetPerMin(params, 1'000'000), 4U);
}

BOOST_AUTO_TEST_SUITE_END()
