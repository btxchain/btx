// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// WP-7 / C5: unit tests for the async ENC-DR verify worker
// (node::MatMulVerifyWorker) and the bounded ENC-DR verdict memo (pow.h).

#include <node/matmul_verify_worker.h>
#include <node/matmul_rc_admission.h>
#include <matmul/matmul_v4_rc_accelerator_scheduler.h>

#include <chainparams.h>
#include <consensus/params.h>
#include <matmul/exact_gemm_resolve.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

using node::MatMulVerifyWorker;

namespace {

bool EnqueueAccepted(MatMulVerifyWorker::EnqueueResult result)
{
    return result == MatMulVerifyWorker::EnqueueResult::Enqueued ||
        result == MatMulVerifyWorker::EnqueueResult::Joined;
}

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

struct ActiveLease {
    std::atomic<int>* active;
    explicit ActiveLease(std::atomic<int>* counter)
        : active{counter}
    {
        ++*active;
    }
    ~ActiveLease() { --*active; }
};

std::shared_ptr<const CBlock> MakeBlock(uint32_t salt)
{
    auto block{std::make_shared<CBlock>()};
    block->nNonce64 = salt; // distinct identity hashes per job
    return block;
}

CBlockHeader MakeProfile1Header(uint64_t nonce, const uint256& digest)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    header.matmul_dim = 4096;
    header.matmul_digest = digest;
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51);
        header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3);
        header.seed_a.data()[i] = static_cast<unsigned char>(0x11);
        header.seed_b.data()[i] = static_cast<unsigned char>(0x22);
    }
    return header;
}

Consensus::Params MakeProfile1ActiveParams()
{
    Consensus::Params params;
    params.fMatMulPOW = true;
    params.nMatMulV4Height = 1;
    params.nMatMulRCHeight = 1;
    params.nMatMulRCProfile = 1;
    params.fMatMulRCUseToyDims = false;
    params.nMatMulV4Dimension = 4096;
    params.powLimit =
        uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    return params;
}

bool ProductionMetalSchedulerTestsEnabled()
{
    const char* enabled = std::getenv("BTX_RUN_PROFILE1_METAL_SCHEDULER_TESTS");
    return enabled != nullptr && std::string{enabled} == "1";
}

bool AdmitRCHeader(node::RCAdmissionStore& store,
                   const CBlockHeader& header,
                   uint64_t keyed_netgroup,
                   const uint256& pow_limit)
{
    node::RCAdmissionTicket ticket;
    uint64_t tries{2'000'000};
    if (!node::GrindRCAdmissionTicket(
            header, pow_limit, ticket, tries)) {
        return false;
    }
    const auto now{std::chrono::steady_clock::now()};
    // This scheduler-only helper already has the complete header, so exercise
    // the authenticated tier. The unknown-header quarantine intentionally
    // rate-limits repeated arbitrary hashes and is covered independently by
    // matmul_rc_admission_tests.
    if (store.RememberKnown(
            ticket, header, keyed_netgroup, pow_limit, now) !=
        node::RCAdmissionStore::RememberResult::Stored) {
        return false;
    }
    node::RCAdmissionTicket accepted;
    return store.Consume(
               header, keyed_netgroup, pow_limit, now, &accepted) &&
           accepted.block_hash == header.GetHash();
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
        BOOST_CHECK(EnqueueAccepted(worker.Enqueue(job)));
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

BOOST_AUTO_TEST_CASE(priority_queue_reserves_authenticated_tip_lane)
{
    const Consensus::Params& params = Params().GetConsensus();
    std::mutex mutex;
    std::condition_variable cv;
    bool release_first{false};
    std::atomic<int> calls{0};
    std::vector<uint64_t> order;
    MatMulVerifyWorker worker{
        params, /*max_threads=*/1,
        [&](const CBlock& block, int32_t, std::optional<int64_t>) {
            const int call{++calls};
            if (call == 1) {
                std::unique_lock<std::mutex> lock(mutex);
                cv.wait(lock, [&] { return release_first; });
            }
            {
                std::lock_guard<std::mutex> lock(mutex);
                order.push_back(block.nNonce64);
            }
            return true;
        }};

    auto enqueue = [&](uint64_t nonce, MatMulVerifyWorker::Priority priority) {
        MatMulVerifyWorker::Job job{
            .block = MakeBlock(nonce),
            .height = 100,
            .priority = priority,
        };
        BOOST_REQUIRE(EnqueueAccepted(worker.Enqueue(job)));
    };
    enqueue(1, MatMulVerifyWorker::Priority::Background);
    BOOST_REQUIRE(WaitFor([&] { return calls.load() == 1; }));
    enqueue(2, MatMulVerifyWorker::Priority::Background);
    enqueue(3, MatMulVerifyWorker::Priority::AuthenticatedTipChild);
    {
        std::lock_guard<std::mutex> lock(mutex);
        release_first = true;
    }
    cv.notify_all();
    BOOST_REQUIRE(WaitFor([&] { return calls.load() == 3; }));
    worker.Stop();
    BOOST_REQUIRE_EQUAL(order.size(), 3U);
    BOOST_CHECK_EQUAL(order[0], 1U);
    BOOST_CHECK_EQUAL(order[1], 3U);
    BOOST_CHECK_EQUAL(order[2], 2U);
}

BOOST_AUTO_TEST_CASE(ticketed_invalid_candidates_cannot_starve_authenticated_tip_lane)
{
    const Consensus::Params params{MakeProfile1ActiveParams()};
    node::RCAdmissionStore admission{{
        .max_entries = 32,
        .max_entries_per_netgroup = 32,
        .ttl = std::chrono::seconds{180},
    }};
    constexpr uint64_t kNetgroup{0x5141554f5441};
    constexpr uint64_t kFirstInvalid{7000};
    constexpr uint64_t kHonestTip{8000};
    constexpr size_t kInvalidCandidates{8};

    std::mutex mutex;
    std::condition_variable cv;
    bool release_first{false};
    std::atomic<int> calls{0};
    std::atomic<int> completions{0};
    std::atomic<int> invalid_completions{0};
    std::atomic<int> honest_completions{0};
    std::atomic<size_t> canceled_after_honest{0};
    std::vector<uint64_t> execution_order;

    MatMulVerifyWorker worker{
        params, /*max_threads=*/1,
        [&](const CBlock& block, int32_t, std::optional<int64_t>) {
            const int call{++calls};
            if (call == 1) {
                std::unique_lock<std::mutex> lock(mutex);
                cv.wait(lock, [&] { return release_first; });
            }
            {
                std::lock_guard<std::mutex> lock(mutex);
                execution_order.push_back(block.nNonce64);
            }
            return block.nNonce64 == kHonestTip;
        }};

    auto enqueue_ticketed =
        [&](uint64_t nonce,
            MatMulVerifyWorker::Priority priority,
            bool honest,
            std::shared_ptr<std::atomic_bool> cancelled = nullptr) {
            uint256 claim;
            claim.data()[0] = honest ? 0x34 : 0x7f;
            claim.data()[1] =
                static_cast<unsigned char>(nonce & 0xffU);
            claim.data()[2] =
                static_cast<unsigned char>((nonce >> 8) & 0xffU);
            const CBlockHeader header{
                MakeProfile1Header(nonce, claim)};
            BOOST_REQUIRE(AdmitRCHeader(
                admission, header, kNetgroup, params.powLimit));
            MatMulVerifyWorker::Job job{
                .height = 100,
                .completion = [&, honest](bool ok) {
                    BOOST_CHECK_EQUAL(ok, honest);
                    if (honest) {
                        canceled_after_honest.store(
                            worker.CancelIf(
                                [](const CBlockHeader&, int32_t) {
                                    return true;
                                }),
                            std::memory_order_relaxed);
                        ++honest_completions;
                    } else {
                        ++invalid_completions;
                    }
                    ++completions;
                },
                .header =
                    std::make_shared<CBlockHeader>(header),
                .priority = priority,
                .cancelled = std::move(cancelled),
            };
            BOOST_REQUIRE(EnqueueAccepted(worker.Enqueue(job)));
        };

    auto first_cancelled{
        std::make_shared<std::atomic_bool>(false)};
    enqueue_ticketed(
        kFirstInvalid,
        MatMulVerifyWorker::Priority::CompetingBranch,
        /*honest=*/false,
        first_cancelled);
    BOOST_REQUIRE(WaitFor([&] { return calls.load() == 1; }));

    for (size_t i = 1; i < kInvalidCandidates; ++i) {
        enqueue_ticketed(
            kFirstInvalid + i,
            MatMulVerifyWorker::Priority::CompetingBranch,
            /*honest=*/false);
    }
    enqueue_ticketed(
        kHonestTip,
        MatMulVerifyWorker::Priority::AuthenticatedTipChild,
        /*honest=*/true);

    // The ticketed candidate already owns the single submitter, but the
    // authenticated-tip arrival must revoke that speculative lease before
    // the candidate can enter a long portable mismatch retry.
    BOOST_CHECK(first_cancelled->load(std::memory_order_relaxed));
    {
        std::lock_guard<std::mutex> lock(mutex);
        release_first = true;
    }
    cv.notify_all();

    BOOST_REQUIRE(WaitFor([&] {
        return honest_completions.load() == 1;
    }));
    worker.Stop();

    BOOST_REQUIRE_GE(execution_order.size(), 2U);
    BOOST_CHECK_EQUAL(execution_order[0], kFirstInvalid);
    BOOST_CHECK_EQUAL(execution_order[1], kHonestTip);
    BOOST_CHECK_EQUAL(honest_completions.load(), 1);
    BOOST_CHECK_EQUAL(invalid_completions.load(), 0);
    BOOST_CHECK_EQUAL(completions.load(), 1);
    BOOST_CHECK_EQUAL(
        canceled_after_honest.load(std::memory_order_relaxed),
        kInvalidCandidates - 1);
    BOOST_CHECK_EQUAL(worker.QueueDepthForTest(), 0U);
}

BOOST_AUTO_TEST_CASE(header_and_body_duplicates_join_one_verdict)
{
    const Consensus::Params& params = Params().GetConsensus();
    BlockingVerify gate;
    std::atomic<int> completions{0};
    MatMulVerifyWorker worker{
        params, /*max_threads=*/1,
        [&](const CBlock&, int32_t, std::optional<int64_t>) {
            return gate.Run();
        }};
    const auto block{MakeBlock(77)};
    auto header{std::make_shared<CBlockHeader>(block->GetBlockHeader())};
    MatMulVerifyWorker::Job header_job{
        .height = 100,
        .completion = [&](bool ok) {
            BOOST_CHECK(ok);
            ++completions;
        },
        .header = header,
        .priority = MatMulVerifyWorker::Priority::CompetingBranch,
    };
    BOOST_REQUIRE(
        worker.Enqueue(header_job) ==
        MatMulVerifyWorker::EnqueueResult::Enqueued);
    BOOST_REQUIRE(WaitFor([&] { return gate.running.load() == 1; }));

    MatMulVerifyWorker::Job body_job{
        .block = block,
        .height = 100,
        .completion = [&](bool ok) {
            BOOST_CHECK(ok);
            ++completions;
        },
        .priority = MatMulVerifyWorker::Priority::AuthenticatedTipChild,
    };
    BOOST_REQUIRE(
        worker.Enqueue(
            body_job, MatMulVerifyWorker::EnqueueMode::JoinOnly) ==
        MatMulVerifyWorker::EnqueueResult::Joined);
    // A tip change may cancel pure speculation, but must not discard the
    // validation completion after a full body has joined that same replay.
    BOOST_CHECK(!worker.Cancel(block->GetHash()));
    gate.Release();
    BOOST_REQUIRE(WaitFor([&] { return completions.load() == 2; }));
    BOOST_CHECK_EQUAL(gate.total_calls.load(), 1);
}

BOOST_AUTO_TEST_CASE(cancelled_header_rejects_body_join_without_sync_signal)
{
    const Consensus::Params& params = Params().GetConsensus();
    BlockingVerify gate;
    std::atomic<int> completions{0};
    MatMulVerifyWorker worker{
        params, /*max_threads=*/1,
        [&](const CBlock&, int32_t, std::optional<int64_t>) {
            return gate.Run();
        }};
    const auto block{MakeBlock(78)};
    MatMulVerifyWorker::Job header_job{
        .height = 100,
        .completion = [&](bool) { ++completions; },
        .header =
            std::make_shared<CBlockHeader>(block->GetBlockHeader()),
        .priority =
            MatMulVerifyWorker::Priority::AuthenticatedTipChild,
    };
    BOOST_REQUIRE(
        worker.Enqueue(
            header_job, MatMulVerifyWorker::EnqueueMode::NewOnly) ==
        MatMulVerifyWorker::EnqueueResult::Enqueued);
    BOOST_REQUIRE(WaitFor([&] { return gate.running.load() == 1; }));
    BOOST_REQUIRE(worker.Cancel(block->GetHash()));

    MatMulVerifyWorker::Job body_job{
        .block = block,
        .height = 100,
        .completion = [&](bool) { ++completions; },
        .priority =
            MatMulVerifyWorker::Priority::AuthenticatedTipChild,
    };
    BOOST_CHECK(
        worker.Enqueue(
            body_job, MatMulVerifyWorker::EnqueueMode::JoinOnly) ==
        MatMulVerifyWorker::EnqueueResult::Deferred);
    BOOST_CHECK(body_job.block != nullptr);
    BOOST_CHECK(body_job.completion);

    gate.Release();
    worker.Stop();
    BOOST_CHECK_EQUAL(completions.load(), 0);
    BOOST_CHECK_EQUAL(gate.total_calls.load(), 1);
}

BOOST_AUTO_TEST_CASE(complete_tip_body_preempts_equal_priority_speculation)
{
    const Consensus::Params& params = Params().GetConsensus();
    BlockingVerify gate;
    std::atomic<int> body_completions{0};
    std::atomic<int> pending_leases{0};
    std::atomic<int> speculative_leases{0};
    std::atomic<int> permanent_rate_debits{1};
    auto speculative_cancelled{
        std::make_shared<std::atomic_bool>(false)};
    MatMulVerifyWorker worker{
        params, /*max_threads=*/1,
        [&](const CBlock& block, int32_t,
            std::optional<int64_t>) {
            if (block.nNonce64 == 90) return gate.Run();
            return true;
        }};

    const auto speculative{MakeBlock(90)};
    MatMulVerifyWorker::Job header_job{
        .height = 100,
        .header = std::make_shared<CBlockHeader>(
            speculative->GetBlockHeader()),
        .priority =
            MatMulVerifyWorker::Priority::AuthenticatedTipChild,
        .cancelled = speculative_cancelled,
        .rc_pending_lease =
            std::make_shared<ActiveLease>(&pending_leases),
        .rc_speculative_lease =
            std::make_shared<ActiveLease>(
                &speculative_leases),
        .equal_priority_handoff_available = true,
    };
    BOOST_REQUIRE(
        worker.Enqueue(header_job) ==
        MatMulVerifyWorker::EnqueueResult::Enqueued);
    BOOST_REQUIRE(WaitFor([&] { return gate.running.load() == 1; }));
    BOOST_CHECK_EQUAL(pending_leases.load(), 1);
    BOOST_CHECK_EQUAL(speculative_leases.load(), 1);

    MatMulVerifyWorker::Job body_job{
        .block = MakeBlock(91),
        .height = 100,
        .completion = [&](bool ok) {
            BOOST_CHECK(ok);
            ++body_completions;
        },
        .priority =
            MatMulVerifyWorker::Priority::AuthenticatedTipChild,
    };
    BOOST_REQUIRE(
        worker.HandoffAuthenticatedTip(body_job) ==
        MatMulVerifyWorker::HandoffResult::HandedOff);
    BOOST_CHECK(
        speculative_cancelled->load(std::memory_order_relaxed));
    BOOST_CHECK_EQUAL(pending_leases.load(), 1);
    BOOST_CHECK_EQUAL(speculative_leases.load(), 0);
    BOOST_CHECK_EQUAL(permanent_rate_debits.load(), 1);

    gate.Release();
    BOOST_REQUIRE(
        WaitFor([&] { return body_completions.load() == 1; }));
    worker.Stop();
    BOOST_CHECK_EQUAL(gate.total_calls.load(), 1);
    BOOST_CHECK_EQUAL(pending_leases.load(), 0);
    BOOST_CHECK_EQUAL(speculative_leases.load(), 0);
    BOOST_CHECK_EQUAL(permanent_rate_debits.load(), 1);
}

BOOST_AUTO_TEST_CASE(paid_cap_one_header_handoff_is_bounded_and_exact)
{
    Consensus::Params params{MakeProfile1ActiveParams()};
    params.nMatMulRCMaxPendingVerifications = 1;
    params.nMatMulRCGlobalVerifyBudgetPerMin = 1;
    params.nMatMulRCPeerVerifyBudgetPerMin = 1;
    node::RCAdmissionStore admission{{
        .max_entries = 8,
        .max_entries_per_netgroup = 4,
        .ttl = std::chrono::seconds{180},
    }};
    constexpr uint64_t kAttackerNetgroup{0xaaa1};
    constexpr uint64_t kHonestNetgroup{0xbbb2};
    const uint256 false_claim{uint256::ONE};
    uint256 honest_claim;
    honest_claim.data()[0] = 2;
    auto false_header{std::make_shared<CBlockHeader>(
        MakeProfile1Header(94, false_claim))};
    auto honest_header{std::make_shared<CBlockHeader>(
        MakeProfile1Header(95, honest_claim))};
    BOOST_REQUIRE(AdmitRCHeader(
        admission, *false_header, kAttackerNetgroup,
        params.powLimit));
    BOOST_REQUIRE(AdmitRCHeader(
        admission, *honest_header, kHonestNetgroup,
        params.powLimit));

    BlockingVerify gate;
    std::atomic<int> honest_completions{0};
    std::atomic<int> pending_leases{0};
    std::atomic<int> speculative_leases{0};
    std::atomic<int> permanent_rate_debits{1};
    std::atomic<int> retargets{0};
    auto false_cancelled{
        std::make_shared<std::atomic_bool>(false)};
    MatMulVerifyWorker worker{
        params, /*max_threads=*/1,
        [&](const CBlock& block, int32_t,
            std::optional<int64_t>) {
            if (block.nNonce64 == 94) return gate.Run();
            return block.nNonce64 == 95;
        }};

    MatMulVerifyWorker::Job false_job{
        .height = 100,
        .header = false_header,
        .priority =
            MatMulVerifyWorker::Priority::AuthenticatedTipChild,
        .cancelled = false_cancelled,
        .rc_pending_lease =
            std::make_shared<ActiveLease>(&pending_leases),
        .rc_speculative_lease =
            std::make_shared<ActiveLease>(
                &speculative_leases),
        .retarget_speculative_lease =
            [&](const uint256& hash) {
                BOOST_CHECK_EQUAL(hash, honest_header->GetHash());
                ++retargets;
            },
        .equal_priority_handoff_available = true,
    };
    BOOST_REQUIRE(
        worker.Enqueue(false_job) ==
        MatMulVerifyWorker::EnqueueResult::Enqueued);
    BOOST_REQUIRE(WaitFor([&] { return gate.running.load() == 1; }));

    MatMulVerifyWorker::Job honest_job{
        .height = 100,
        .completion = [&](bool ok) {
            BOOST_CHECK(ok);
            ++honest_completions;
        },
        .header = honest_header,
        .priority =
            MatMulVerifyWorker::Priority::AuthenticatedTipChild,
    };
    BOOST_REQUIRE(
        worker.CanHandoffAuthenticatedTip(*honest_header, 100));
    BOOST_REQUIRE(
        worker.HandoffAuthenticatedTip(honest_job) ==
        MatMulVerifyWorker::HandoffResult::HandedOff);
    BOOST_CHECK(false_cancelled->load(std::memory_order_relaxed));
    BOOST_CHECK_EQUAL(pending_leases.load(), 1);
    BOOST_CHECK_EQUAL(speculative_leases.load(), 1);
    BOOST_CHECK_EQUAL(permanent_rate_debits.load(), 1);
    BOOST_CHECK_EQUAL(retargets.load(), 1);

    auto third_header{std::make_shared<CBlockHeader>(
        MakeProfile1Header(96, false_claim))};
    MatMulVerifyWorker::Job third_job{
        .height = 100,
        .header = third_header,
        .priority =
            MatMulVerifyWorker::Priority::AuthenticatedTipChild,
    };
    BOOST_CHECK(
        !worker.CanHandoffAuthenticatedTip(*third_header, 100));
    BOOST_CHECK(
        worker.HandoffAuthenticatedTip(third_job) ==
        MatMulVerifyWorker::HandoffResult::Deferred);

    gate.Release();
    BOOST_REQUIRE(WaitFor(
        [&] { return honest_completions.load() == 1; }));
    worker.Stop();
    BOOST_CHECK_EQUAL(pending_leases.load(), 0);
    BOOST_CHECK_EQUAL(speculative_leases.load(), 0);
    BOOST_CHECK_EQUAL(permanent_rate_debits.load(), 1);
    BOOST_CHECK_EQUAL(retargets.load(), 1);
}

BOOST_AUTO_TEST_CASE(cancel_stale_queued_job_suppresses_completion)
{
    const Consensus::Params& params = Params().GetConsensus();
    BlockingVerify gate;
    std::atomic<int> completions{0};
    MatMulVerifyWorker worker{
        params, /*max_threads=*/1,
        [&](const CBlock&, int32_t, std::optional<int64_t>) {
            return gate.Run();
        }};
    MatMulVerifyWorker::Job active{
        .block = MakeBlock(80),
        .height = 100,
        .completion = [&](bool) { ++completions; },
    };
    BOOST_REQUIRE(EnqueueAccepted(worker.Enqueue(active)));
    BOOST_REQUIRE(WaitFor([&] { return gate.running.load() == 1; }));

    const auto stale_header{
        std::make_shared<CBlockHeader>(
            MakeBlock(81)->GetBlockHeader())};
    MatMulVerifyWorker::Job stale{
        .height = 99,
        .completion = [&](bool) { ++completions; },
        .header = stale_header,
    };
    BOOST_REQUIRE(EnqueueAccepted(worker.Enqueue(stale)));
    BOOST_CHECK(worker.Cancel(stale_header->GetHash()));
    BOOST_CHECK_EQUAL(worker.QueueDepthForTest(), 0U);
    gate.Release();
    BOOST_REQUIRE(WaitFor([&] { return completions.load() == 1; }));
    BOOST_CHECK_EQUAL(gate.total_calls.load(), 1);
}

BOOST_AUTO_TEST_CASE(cancelled_running_replay_runs_retryable_cleanup_only)
{
    const Consensus::Params& params = Params().GetConsensus();
    BlockingVerify gate;
    std::atomic<int> verdict_completions{0};
    std::atomic<int> retryable_cleanups{0};
    MatMulVerifyWorker worker{
        params, /*max_threads=*/1,
        [&](const CBlock&, int32_t, std::optional<int64_t>) {
            return gate.Run();
        }};

    const auto speculative_header{
        std::make_shared<CBlockHeader>(
            MakeBlock(82)->GetBlockHeader())};
    MatMulVerifyWorker::Job speculative{
        .height = 100,
        .completion = [&](bool) { ++verdict_completions; },
        .retryable_failure = [&] { ++retryable_cleanups; },
        .header = speculative_header,
        .priority = MatMulVerifyWorker::Priority::CompetingBranch,
    };
    BOOST_REQUIRE(EnqueueAccepted(worker.Enqueue(speculative)));
    BOOST_REQUIRE(WaitFor([&] { return gate.running.load() == 1; }));

    MatMulVerifyWorker::Job authenticated_tip{
        .height = 100,
        .header = std::make_shared<CBlockHeader>(
            MakeBlock(83)->GetBlockHeader()),
        .priority =
            MatMulVerifyWorker::Priority::AuthenticatedTipChild,
    };
    BOOST_REQUIRE(EnqueueAccepted(worker.Enqueue(authenticated_tip)));
    gate.Release();
    BOOST_REQUIRE(WaitFor(
        [&] { return retryable_cleanups.load() == 1; }));
    BOOST_CHECK_EQUAL(verdict_completions.load(), 0);
    BOOST_REQUIRE(WaitFor([&] { return gate.total_calls.load() == 2; }));
}

BOOST_AUTO_TEST_CASE(full_body_is_not_preempted_by_authenticated_tip)
{
    const Consensus::Params& params = Params().GetConsensus();
    BlockingVerify gate;
    std::atomic<int> body_completions{0};
    auto body_cancelled{
        std::make_shared<std::atomic_bool>(false)};
    MatMulVerifyWorker worker{
        params, /*max_threads=*/1,
        [&](const CBlock&, int32_t, std::optional<int64_t>) {
            return gate.Run();
        }};

    MatMulVerifyWorker::Job body_job{
        .block = MakeBlock(89),
        .height = 100,
        .completion = [&](bool ok) {
            BOOST_CHECK(ok);
            ++body_completions;
        },
        .priority = MatMulVerifyWorker::Priority::Background,
        .cancelled = body_cancelled,
    };
    BOOST_REQUIRE(EnqueueAccepted(worker.Enqueue(body_job)));
    BOOST_REQUIRE(WaitFor([&] { return gate.running.load() == 1; }));

    MatMulVerifyWorker::Job tip_job{
        .height = 101,
        .header = std::make_shared<CBlockHeader>(
            MakeBlock(93)->GetBlockHeader()),
        .priority =
            MatMulVerifyWorker::Priority::AuthenticatedTipChild,
    };
    BOOST_REQUIRE(EnqueueAccepted(worker.Enqueue(tip_job)));
    BOOST_CHECK(
        !body_cancelled->load(std::memory_order_relaxed));

    gate.Release();
    BOOST_REQUIRE(
        WaitFor([&] { return gate.total_calls.load() == 2; }));
    BOOST_REQUIRE(
        WaitFor([&] { return body_completions.load() == 1; }));
}

BOOST_AUTO_TEST_CASE(profile1_metal_back_to_back_blocks)
{
    if (!ProductionMetalSchedulerTestsEnabled()) {
        BOOST_TEST_MESSAGE(
            "Set BTX_RUN_PROFILE1_METAL_SCHEDULER_TESTS=1 to run the off-CI "
            "full-Metal production Profile-1 scheduler campaign.");
        return;
    }

    const auto resolved = matmul_v4::accel::ResolveExactGemmBackendForRC();
    BOOST_REQUIRE_MESSAGE(
        resolved.self_qualified && resolved.backend.gemm_s8s8 != nullptr,
        "Profile-1 scheduler campaign requires a self-qualified ExactReplay backend: "
            << resolved.reason);
    BOOST_REQUIRE_MESSAGE(
        resolved.provider.rfind("metal_", 0) == 0,
        "Profile-1 scheduler campaign requires Metal, resolved " << resolved.provider);

    const Consensus::Params consensus = MakeProfile1ActiveParams();
    std::atomic<int> completed{0};
    std::mutex walls_mutex;
    std::vector<double> completion_walls;
    MatMulVerifyWorker worker{consensus, /*max_threads=*/1};

    const auto campaign_start = std::chrono::steady_clock::now();
    const std::pair<uint64_t, uint256> blocks[]{
        {1002, uint256{"1f3cd6428314d9e47b73d8f2e547cf572b1706b6711b82e92fe6f528b2445a55"}},
        {1005, uint256{"7fa1a5426c57884722cceb3214d12a4e8674fa877b907d3a98f0fddf44d3e10e"}},
    };
    for (const auto& [nonce, digest] : blocks) {
        auto header = std::make_shared<CBlockHeader>(
            MakeProfile1Header(nonce, digest));
        MatMulVerifyWorker::Job job{
            .height = 100,
            .completion = [&](bool ok) {
                if (!ok) return;
                {
                    std::lock_guard<std::mutex> lock(walls_mutex);
                    completion_walls.push_back(std::chrono::duration<double>(
                        std::chrono::steady_clock::now() - campaign_start).count());
                }
                ++completed;
            },
            .header = std::move(header),
            .priority = MatMulVerifyWorker::Priority::AuthenticatedTipChild,
        };
        BOOST_REQUIRE(EnqueueAccepted(worker.Enqueue(job)));
    }

    BOOST_REQUIRE_MESSAGE(
        WaitFor(
            [&] { return completed.load() == 2; },
            std::chrono::milliseconds{180000}),
        "two immediately queued Profile-1 ExactReplay blocks did not drain in 180s");
    const double drain_s = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - campaign_start).count();
    worker.Stop();

    BOOST_REQUIRE_EQUAL(completion_walls.size(), 2U);
    BOOST_CHECK_EQUAL(worker.QueueDepthForTest(), 0U);
    BOOST_CHECK_LT(drain_s, 90.0);
    const double first_s = completion_walls[0];
    const double second_s = completion_walls[1] - completion_walls[0];
    BOOST_TEST_MESSAGE(
        "Profile-1 Metal back-to-back consensus: first=" << first_s
        << "s second=" << second_s << "s immediate_drain=" << drain_s
        << "s queue_depth_end=" << worker.QueueDepthForTest());
}

BOOST_AUTO_TEST_CASE(profile1_metal_ticketed_invalid_candidates_do_not_starve_tip)
{
    if (!ProductionMetalSchedulerTestsEnabled()) {
        BOOST_TEST_MESSAGE(
            "Set BTX_RUN_PROFILE1_METAL_SCHEDULER_TESTS=1 to run the off-CI "
            "full-Metal production Profile-1 scheduler campaign.");
        return;
    }

    const auto resolved = matmul_v4::accel::ResolveExactGemmBackendForRC();
    BOOST_REQUIRE_MESSAGE(
        resolved.self_qualified && resolved.backend.gemm_s8s8 != nullptr,
        "Profile-1 scheduler campaign requires a self-qualified ExactReplay backend: "
            << resolved.reason);
    BOOST_REQUIRE_MESSAGE(
        resolved.provider.rfind("metal_", 0) == 0,
        "Profile-1 scheduler campaign requires Metal, resolved " << resolved.provider);

    const Consensus::Params consensus{MakeProfile1ActiveParams()};
    node::RCAdmissionStore admission{{
        .max_entries = 16,
        .max_entries_per_netgroup = 16,
        .ttl = std::chrono::seconds{180},
    }};
    constexpr uint64_t kNetgroup{0x4d4554414c};
    constexpr uint64_t kFirstInvalid{1000};
    constexpr uint64_t kHonestTip{1002};
    const uint256 invalid_claim{uint256::ONE};
    const uint256 honest_claim{
        "1f3cd6428314d9e47b73d8f2e547cf572b1706b6711b82e92fe6f528b2445a55"};

    std::atomic<int> honest_completions{0};
    std::atomic<int> invalid_completions{0};
    std::atomic<size_t> canceled_after_honest{0};
    std::mutex timing_mutex;
    double honest_after_flood_s{0};
    MatMulVerifyWorker worker{consensus, /*max_threads=*/1};
    const auto flood_start{std::chrono::steady_clock::now()};

    auto enqueue_ticketed =
        [&](uint64_t nonce,
            const uint256& digest,
            MatMulVerifyWorker::Priority priority,
            bool honest,
            std::shared_ptr<std::atomic_bool> cancelled = nullptr) {
            auto header{std::make_shared<CBlockHeader>(
                MakeProfile1Header(nonce, digest))};
            BOOST_REQUIRE(AdmitRCHeader(
                admission, *header, kNetgroup, consensus.powLimit));
            const uint256 hash{header->GetHash()};
            MatMulVerifyWorker::Job job{
                .height = 100,
                .completion = [&, honest](bool ok) {
                    if (honest) {
                        BOOST_CHECK(ok);
                        if (!ok) return;
                        canceled_after_honest.store(
                            worker.CancelIf(
                                [](const CBlockHeader&, int32_t) {
                                    return true;
                                }),
                            std::memory_order_relaxed);
                        {
                            std::lock_guard<std::mutex> lock(timing_mutex);
                            honest_after_flood_s =
                                std::chrono::duration<double>(
                                    std::chrono::steady_clock::now() -
                                    flood_start)
                                    .count();
                        }
                        ++honest_completions;
                    } else {
                        BOOST_CHECK(!ok);
                        ++invalid_completions;
                    }
                },
                .header = std::move(header),
                .priority = priority,
                .cancelled = std::move(cancelled),
            };
            BOOST_REQUIRE(EnqueueAccepted(worker.Enqueue(job)));
            return hash;
        };

    auto first_cancelled{
        std::make_shared<std::atomic_bool>(false)};
    const uint256 first_hash{enqueue_ticketed(
        kFirstInvalid,
        invalid_claim,
        MatMulVerifyWorker::Priority::CompetingBranch,
        /*honest=*/false,
        first_cancelled)};
    BOOST_REQUIRE_MESSAGE(
        WaitFor(
            [&] {
                return worker.Contains(first_hash) &&
                       worker.QueueDepthForTest() == 0;
            },
            std::chrono::milliseconds{30000}),
        "ticketed invalid candidate did not begin ExactReplay");
    std::this_thread::sleep_for(std::chrono::milliseconds{500});

    enqueue_ticketed(
        1001,
        invalid_claim,
        MatMulVerifyWorker::Priority::CompetingBranch,
        /*honest=*/false);
    enqueue_ticketed(
        1003,
        invalid_claim,
        MatMulVerifyWorker::Priority::CompetingBranch,
        /*honest=*/false);
    enqueue_ticketed(
        kHonestTip,
        honest_claim,
        MatMulVerifyWorker::Priority::AuthenticatedTipChild,
        /*honest=*/true);

    BOOST_CHECK(first_cancelled->load(std::memory_order_relaxed));
    const auto preempt_start{std::chrono::steady_clock::now()};
    BOOST_REQUIRE_MESSAGE(
        WaitFor(
            [&] { return !worker.Contains(first_hash); },
            std::chrono::milliseconds{30000}),
        "authenticated-tip arrival did not preempt ticketed invalid replay");
    const double preempt_s{std::chrono::duration<double>(
        std::chrono::steady_clock::now() - preempt_start).count()};

    BOOST_REQUIRE_MESSAGE(
        WaitFor(
            [&] { return honest_completions.load() == 1; },
            std::chrono::milliseconds{90000}),
        "ticketed invalid candidates starved the authenticated-tip lane");
    worker.Stop();

    BOOST_CHECK_LT(preempt_s, 15.0);
    BOOST_CHECK_LT(honest_after_flood_s, 90.0);
    BOOST_CHECK_EQUAL(invalid_completions.load(), 0);
    BOOST_CHECK_EQUAL(
        canceled_after_honest.load(std::memory_order_relaxed), 2U);
    BOOST_CHECK_EQUAL(worker.QueueDepthForTest(), 0U);
    BOOST_TEST_MESSAGE(
        "Profile-1 Metal ticketed-invalid starvation: preempt="
        << preempt_s << "s honest_verdict_after_flood="
        << honest_after_flood_s
        << "s invalid_completions=" << invalid_completions.load());
}

BOOST_AUTO_TEST_CASE(profile1_metal_three_branch_reorg_cancels_stale_work)
{
    if (!ProductionMetalSchedulerTestsEnabled()) {
        BOOST_TEST_MESSAGE(
            "Set BTX_RUN_PROFILE1_METAL_SCHEDULER_TESTS=1 to run the off-CI "
            "full-Metal production Profile-1 scheduler campaign.");
        return;
    }

    const auto resolved = matmul_v4::accel::ResolveExactGemmBackendForRC();
    BOOST_REQUIRE_MESSAGE(
        resolved.self_qualified && resolved.backend.gemm_s8s8 != nullptr,
        "Profile-1 scheduler campaign requires a self-qualified ExactReplay backend: "
            << resolved.reason);
    BOOST_REQUIRE_MESSAGE(
        resolved.provider.rfind("metal_", 0) == 0,
        "Profile-1 scheduler campaign requires Metal, resolved " << resolved.provider);

    constexpr uint64_t kStaleRunning{1000};
    constexpr uint64_t kStaleQueued{1001};
    constexpr uint64_t kCanonical{1006};
    const Consensus::Params consensus = MakeProfile1ActiveParams();
    std::atomic<int> canonical_completions{0};
    MatMulVerifyWorker worker{consensus, /*max_threads=*/1};

    auto enqueue_header = [&](uint64_t nonce, MatMulVerifyWorker::Priority priority,
                              const uint256& digest, bool canonical) {
        auto header = std::make_shared<CBlockHeader>(
            MakeProfile1Header(nonce, digest));
        MatMulVerifyWorker::Job job{
            .height = 100,
            .completion = [&, canonical](bool ok) {
                if (canonical && ok) ++canonical_completions;
            },
            .header = std::move(header),
            .priority = priority,
        };
        BOOST_REQUIRE(EnqueueAccepted(worker.Enqueue(job)));
    };

    enqueue_header(
        kStaleRunning, MatMulVerifyWorker::Priority::CompetingBranch,
        uint256{"ad578b1120d52083d05d7ceb78406a07bd87f59bc6991f2969930a8bd863bb49"},
        false);
    const uint256 stale_running_hash{
        MakeProfile1Header(
            kStaleRunning,
            uint256{"ad578b1120d52083d05d7ceb78406a07bd87f59bc6991f2969930a8bd863bb49"})
            .GetHash()};
    BOOST_REQUIRE_MESSAGE(
        WaitFor(
            [&] {
                return worker.Contains(stale_running_hash) &&
                       worker.QueueDepthForTest() == 0;
            },
            std::chrono::milliseconds{30000}),
        "stale branch did not begin ExactReplay");
    std::this_thread::sleep_for(std::chrono::milliseconds{500});
    enqueue_header(
        kStaleQueued, MatMulVerifyWorker::Priority::Background,
        uint256{"acf62f5cd9906b761be9fcc0aee86ad94a530762a93685f53706d060b23227d1"},
        false);
    enqueue_header(
        kCanonical, MatMulVerifyWorker::Priority::AuthenticatedTipChild,
        uint256{"2bb88109cd0fb6735ad7dbd6c3cc606b91a7a36e47922505244421693ceb727f"},
        true);
    BOOST_REQUIRE_EQUAL(worker.QueueDepthForTest(), 2U);

    const auto cancel_start = std::chrono::steady_clock::now();
    const size_t canceled = worker.CancelIf(
        [&](const CBlockHeader& header, int32_t) {
            return header.nNonce64 != kCanonical;
        });
    BOOST_REQUIRE_EQUAL(canceled, 2U);
    BOOST_REQUIRE_EQUAL(worker.QueueDepthForTest(), 1U);
    BOOST_REQUIRE_MESSAGE(
        WaitFor(
            [&] { return !worker.Contains(stale_running_hash); },
            std::chrono::milliseconds{90000}),
        "running stale branch did not stop within one block interval");
    const double cancel_latency_s = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - cancel_start).count();

    BOOST_REQUIRE_MESSAGE(
        WaitFor(
            [&] { return canonical_completions.load() == 1; },
            std::chrono::milliseconds{90000}),
        "canonical branch did not finish within one block interval after reorg");
    const double canonical_after_reorg_s = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - cancel_start).count();
    worker.Stop();

    BOOST_CHECK_EQUAL(worker.QueueDepthForTest(), 0U);
    BOOST_CHECK_LT(cancel_latency_s, 90.0);
    BOOST_CHECK_LT(canonical_after_reorg_s, 90.0);
    BOOST_TEST_MESSAGE(
        "Profile-1 Metal three-branch reorg: canceled=" << canceled
        << " stale_cancel_latency=" << cancel_latency_s
        << "s canonical_verdict_after_reorg=" << canonical_after_reorg_s
        << "s");
}

// Design test A.10 #3: Stop() with queued jobs runs no consensus completion;
// it does run retryable cleanup and releases every captured slot.
BOOST_AUTO_TEST_CASE(stop_drains_queue_without_completions)
{
    const Consensus::Params& params = Params().GetConsensus();
    BlockingVerify gate;
    std::atomic<int> completions{0};
    std::atomic<int> retryable_cleanups{0};
    std::atomic<int> slots_released{0};
    MatMulVerifyWorker worker{params, /*max_threads=*/1,
                              [&](const CBlock&, int32_t, std::optional<int64_t>) { return gate.Run(); }};

    constexpr int kJobs{4};
    for (int i = 0; i < kJobs; ++i) {
        auto sentinel{std::make_shared<SlotSentinel>(&slots_released)};
        MatMulVerifyWorker::Job job{
            .block = MakeBlock(i),
            .height = 100,
            .completion =
                [&completions, sentinel](bool) { ++completions; },
            .retryable_failure =
                [&retryable_cleanups] { ++retryable_cleanups; },
        };
        BOOST_CHECK(EnqueueAccepted(worker.Enqueue(job)));
    }
    BOOST_CHECK(WaitFor([&] { return gate.running.load() == 1; }));
    BOOST_CHECK_EQUAL(worker.QueueDepthForTest(), kJobs - 1);

    // Let the in-flight job finish while Stop() joins; queued jobs must be
    // released without a fabricated consensus verdict.
    gate.Release();
    worker.Stop();
    BOOST_CHECK_EQUAL(completions.load(), 1);       // only the in-flight job completed
    BOOST_CHECK_EQUAL(retryable_cleanups.load(), kJobs - 1);
    BOOST_CHECK_EQUAL(slots_released.load(), kJobs); // but every slot was released

    // Enqueue after Stop() is distinguishable from a policy deferral and
    // leaves the job intact. Network callers still fail closed rather than
    // running expensive validation synchronously.
    MatMulVerifyWorker::Job late{MakeBlock(99), /*height=*/100, /*parent_mtp=*/std::nullopt,
                                 [&](bool) { ++completions; }};
    BOOST_CHECK(
        worker.Enqueue(late) ==
        MatMulVerifyWorker::EnqueueResult::Stopped);
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

BOOST_AUTO_TEST_CASE(encdr_assumevalid_trust_pin_refcounts)
{
    uint256 hash;
    hash.data()[0] = 0xB7;
    hash.data()[1] = 0x41;

    BOOST_CHECK(!IsMatMulEncDrAssumeValidTrustPinned(hash));
    PinMatMulEncDrAssumeValidTrust(hash);
    PinMatMulEncDrAssumeValidTrust(hash);
    BOOST_CHECK(IsMatMulEncDrAssumeValidTrustPinned(hash));
    UnpinMatMulEncDrAssumeValidTrust(hash);
    BOOST_CHECK(IsMatMulEncDrAssumeValidTrustPinned(hash));
    UnpinMatMulEncDrAssumeValidTrust(hash);
    BOOST_CHECK(!IsMatMulEncDrAssumeValidTrustPinned(hash));
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
    BOOST_CHECK(EnqueueAccepted(worker.Enqueue(with_mtp)));
    BOOST_CHECK(WaitFor([&] { return completions.load() == 1; }));
    BOOST_CHECK_EQUAL(seen_mtp.load(), 1);
    BOOST_CHECK_EQUAL(seen_nullopt.load(), 0);

    MatMulVerifyWorker::Job without_mtp{MakeBlock(2), /*height=*/42, std::nullopt,
                                        [&](bool ok) {
                                            BOOST_CHECK(!ok);
                                            ++completions;
                                        }};
    BOOST_CHECK(EnqueueAccepted(worker.Enqueue(without_mtp)));
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

BOOST_AUTO_TEST_CASE(rc_accelerator_scheduler_prioritizes_and_preempts)
{
    using Scheduler = matmul::v4::rc::RCAcceleratorScheduler;
    auto& scheduler{matmul::v4::rc::GetRCAcceleratorScheduler()};
    BOOST_REQUIRE(scheduler.ResetStatsForTest());

    std::atomic_bool candidate_cancelled{false};
    auto candidate{scheduler.Acquire(
        Scheduler::Priority::CandidateMining, &candidate_cancelled,
        "candidate")};
    BOOST_REQUIRE(candidate);

    std::mutex order_mutex;
    std::vector<Scheduler::Priority> order;
    auto wait_for_device = [&](Scheduler::Priority priority,
                               std::atomic_bool& cancelled,
                               const char* label) {
        auto lease{scheduler.Acquire(priority, &cancelled, label)};
        if (lease) {
            std::lock_guard<std::mutex> lock(order_mutex);
            order.push_back(priority);
        }
    };

    std::atomic_bool speculative_cancelled{false};
    std::atomic_bool winner_cancelled{false};
    std::atomic_bool tip_cancelled{false};
    std::thread speculative{
        wait_for_device, Scheduler::Priority::SpeculativeValidation,
        std::ref(speculative_cancelled), "speculative"};
    BOOST_REQUIRE(WaitFor(
        [&] { return scheduler.GetStats().queue_depth == 1; }));
    std::thread winner{
        wait_for_device, Scheduler::Priority::WinnerReseal,
        std::ref(winner_cancelled), "winner"};
    BOOST_REQUIRE(WaitFor(
        [&] { return scheduler.GetStats().queue_depth == 2; }));
    std::thread tip{
        wait_for_device, Scheduler::Priority::TipValidation,
        std::ref(tip_cancelled), "tip"};
    BOOST_REQUIRE(WaitFor([&] {
        return scheduler.GetStats().queue_depth == 3 &&
            candidate_cancelled.load(std::memory_order_relaxed);
    }));

    candidate = {};
    tip.join();
    winner.join();
    speculative.join();

    BOOST_REQUIRE_EQUAL(order.size(), 3U);
    BOOST_CHECK(order[0] == Scheduler::Priority::TipValidation);
    BOOST_CHECK(order[1] == Scheduler::Priority::WinnerReseal);
    BOOST_CHECK(order[2] ==
                Scheduler::Priority::SpeculativeValidation);
    const auto stats{scheduler.GetStats()};
    BOOST_CHECK_EQUAL(stats.requests, 4U);
    BOOST_CHECK_EQUAL(stats.acquisitions, 4U);
    BOOST_CHECK_EQUAL(stats.completions, 4U);
    BOOST_CHECK_EQUAL(stats.preemption_requests, 1U);
    BOOST_CHECK_GE(stats.queue_high_water, 3U);
    BOOST_CHECK(!stats.active);
}

BOOST_AUTO_TEST_CASE(rc_accelerator_scheduler_cancelled_wait_is_retryable)
{
    using Scheduler = matmul::v4::rc::RCAcceleratorScheduler;
    auto& scheduler{matmul::v4::rc::GetRCAcceleratorScheduler()};
    BOOST_REQUIRE(scheduler.ResetStatsForTest());

    std::atomic_bool tip_cancelled{false};
    auto tip{scheduler.Acquire(
        Scheduler::Priority::TipValidation, &tip_cancelled, "tip")};
    BOOST_REQUIRE(tip);

    std::atomic_bool speculative_cancelled{false};
    std::atomic_bool acquired{false};
    std::thread speculative{[&] {
        auto lease{scheduler.Acquire(
            Scheduler::Priority::SpeculativeValidation,
            &speculative_cancelled, "speculative")};
        acquired.store(static_cast<bool>(lease),
                       std::memory_order_relaxed);
    }};
    BOOST_REQUIRE(WaitFor(
        [&] { return scheduler.GetStats().queue_depth == 1; }));
    speculative_cancelled.store(true, std::memory_order_relaxed);
    scheduler.NotifyCancellation();
    speculative.join();
    BOOST_CHECK(!acquired.load(std::memory_order_relaxed));
    BOOST_CHECK_EQUAL(scheduler.GetStats().cancelled_waits, 1U);

    tip = {};
    BOOST_CHECK(!scheduler.GetStats().active);
}

BOOST_AUTO_TEST_CASE(
    rc_worker_cancelled_scheduler_wait_runs_delivery_cleanup)
{
    using Scheduler = matmul::v4::rc::RCAcceleratorScheduler;
    auto& scheduler{matmul::v4::rc::GetRCAcceleratorScheduler()};
    BOOST_REQUIRE(scheduler.ResetStatsForTest());

    std::atomic_bool owner_cancelled{false};
    auto owner{scheduler.Acquire(
        Scheduler::Priority::TipValidation, &owner_cancelled,
        "existing-tip-validation")};
    BOOST_REQUIRE(owner);

    Consensus::Params params{MakeProfile1ActiveParams()};
    MatMulVerifyWorker worker{params, /*max_threads=*/1};
    uint256 claim;
    claim.data()[0] = 0x5a;
    auto header{std::make_shared<CBlockHeader>(
        MakeProfile1Header(0x5155, claim))};
    const uint256 hash{header->GetHash()};
    std::atomic<int> retryable_cleanups{0};
    std::atomic<int> consensus_completions{0};
    MatMulVerifyWorker::Job job{
        .height = 100,
        .completion = [&](bool) { ++consensus_completions; },
        .retryable_failure = [&] { ++retryable_cleanups; },
        .header = std::move(header),
        .priority =
            MatMulVerifyWorker::Priority::AuthenticatedTipChild,
    };
    BOOST_REQUIRE(
        worker.Enqueue(job) ==
        MatMulVerifyWorker::EnqueueResult::Enqueued);
    BOOST_REQUIRE(WaitFor(
        [&] { return scheduler.GetStats().queue_depth == 1; }));

    BOOST_REQUIRE(worker.Cancel(hash));
    BOOST_REQUIRE(WaitFor(
        [&] { return retryable_cleanups.load() == 1; }));
    BOOST_CHECK_EQUAL(consensus_completions.load(), 0);
    BOOST_CHECK(!worker.Contains(hash));
    BOOST_CHECK_EQUAL(scheduler.GetStats().cancelled_waits, 1U);

    worker.Stop();
    owner = {};
    BOOST_CHECK(!scheduler.GetStats().active);
}

BOOST_AUTO_TEST_CASE(
    rc_accelerator_scheduler_observes_external_miner_abort)
{
    using Scheduler = matmul::v4::rc::RCAcceleratorScheduler;
    auto& scheduler{matmul::v4::rc::GetRCAcceleratorScheduler()};
    BOOST_REQUIRE(scheduler.ResetStatsForTest());

    std::atomic_bool tip_preempted{false};
    auto tip{scheduler.Acquire(
        Scheduler::Priority::TipValidation, &tip_preempted, "tip")};
    BOOST_REQUIRE(tip);

    std::atomic_bool candidate_preempted{false};
    std::atomic_bool miner_abort{false};
    std::atomic_bool acquired{true};
    std::thread candidate{[&] {
        auto lease{scheduler.Acquire(
            Scheduler::Priority::CandidateMining,
            &candidate_preempted, "candidate", &miner_abort)};
        acquired.store(static_cast<bool>(lease),
                       std::memory_order_relaxed);
    }};
    BOOST_REQUIRE(WaitFor(
        [&] { return scheduler.GetStats().queue_depth == 1; }));
    miner_abort.store(true, std::memory_order_relaxed);
    scheduler.NotifyCancellation();
    candidate.join();

    BOOST_CHECK(!acquired.load(std::memory_order_relaxed));
    BOOST_CHECK(!candidate_preempted.load(std::memory_order_relaxed));
    BOOST_CHECK_EQUAL(scheduler.GetStats().cancelled_waits, 1U);
    tip = {};
    BOOST_CHECK(!scheduler.GetStats().active);
}

BOOST_AUTO_TEST_CASE(
    rc_accelerator_scheduler_release_identity_and_lifecycle_readiness)
{
    using Scheduler = matmul::v4::rc::RCAcceleratorScheduler;
    auto& scheduler{matmul::v4::rc::GetRCAcceleratorScheduler()};
    BOOST_REQUIRE(scheduler.ResetStatsForTest());

    std::atomic_bool cancelled{false};
    {
        auto lease{scheduler.Acquire(
            Scheduler::Priority::CandidateMining, &cancelled,
            "candidate")};
        BOOST_REQUIRE(lease);
        BOOST_CHECK(!scheduler.TryMismatchedReleaseForTest(
            Scheduler::Priority::WinnerReseal,
            lease.TokenForTest() + 1));
        BOOST_CHECK(scheduler.GetStats().active);
        BOOST_CHECK_EQUAL(
            scheduler.GetStats().release_invariant_violations, 1U);
    }
    {
        auto lease{scheduler.Acquire(
            Scheduler::Priority::WinnerReseal, &cancelled,
            "winner")};
        BOOST_REQUIRE(lease);
    }
    {
        auto lease{scheduler.Acquire(
            Scheduler::Priority::TipValidation, &cancelled,
            "tip")};
        BOOST_REQUIRE(lease);
    }

    auto assessment{scheduler.AssessLifecycle(90.0)};
    BOOST_CHECK(assessment.candidate_measured);
    BOOST_CHECK(assessment.winner_reseal_measured);
    BOOST_CHECK(assessment.tip_validation_measured);
    BOOST_CHECK(!assessment.authenticated_relay_measured);
    BOOST_CHECK(!assessment.complete_sample_set);
    BOOST_CHECK(!assessment.operationally_ready);

    scheduler.RecordAuthenticatedRelaySample(0.25);
    assessment = scheduler.AssessLifecycle(90.0);
    BOOST_CHECK(assessment.complete_sample_set);
    BOOST_CHECK(assessment.within_target_spacing);
    BOOST_CHECK(!assessment.hardware_evidence_gates_passed);
    BOOST_CHECK(!assessment.operationally_ready);
    BOOST_CHECK_CLOSE(
        assessment.authenticated_relay_s, 0.25, 0.001);
    BOOST_CHECK_GT(assessment.complete_lifecycle_s, 0.0);
}

BOOST_AUTO_TEST_CASE(
    rc_accelerator_scheduler_deterministic_contention_stress)
{
    using Scheduler = matmul::v4::rc::RCAcceleratorScheduler;
    auto& scheduler{matmul::v4::rc::GetRCAcceleratorScheduler()};
    BOOST_REQUIRE(scheduler.ResetStatsForTest());

    // CI-scale contention rehearsal: repeatedly occupy the candidate lane,
    // enqueue one request from every validation/reseal class, then verify
    // priority handoff and exact ownership release. This is deterministic and
    // complements the multi-daemon IBD/competing-tip functional campaign.
    constexpr size_t rounds{12};
    for (size_t round = 0; round < rounds; ++round) {
        std::atomic_bool candidate_cancelled{false};
        auto candidate{scheduler.Acquire(
            Scheduler::Priority::CandidateMining,
            &candidate_cancelled, "candidate-soak")};
        BOOST_REQUIRE(candidate);

        std::mutex order_mutex;
        std::vector<Scheduler::Priority> order;
        auto waiter = [&](Scheduler::Priority priority,
                          std::atomic_bool& cancelled,
                          const char* label) {
            auto lease{
                scheduler.Acquire(priority, &cancelled, label)};
            if (!lease) return;
            std::lock_guard<std::mutex> lock{order_mutex};
            order.push_back(priority);
        };
        std::atomic_bool speculative_cancelled{false};
        std::atomic_bool reseal_cancelled{false};
        std::atomic_bool tip_cancelled{false};
        std::thread speculative{
            waiter, Scheduler::Priority::SpeculativeValidation,
            std::ref(speculative_cancelled), "speculative-soak"};
        BOOST_REQUIRE(WaitFor(
            [&] { return scheduler.GetStats().queue_depth == 1; }));
        std::thread reseal{
            waiter, Scheduler::Priority::WinnerReseal,
            std::ref(reseal_cancelled), "reseal-soak"};
        BOOST_REQUIRE(WaitFor(
            [&] { return scheduler.GetStats().queue_depth == 2; }));
        std::thread tip{
            waiter, Scheduler::Priority::TipValidation,
            std::ref(tip_cancelled), "tip-soak"};
        BOOST_REQUIRE(WaitFor([&] {
            return scheduler.GetStats().queue_depth == 3 &&
                candidate_cancelled.load(std::memory_order_relaxed);
        }));
        candidate = {};
        tip.join();
        reseal.join();
        speculative.join();
        BOOST_REQUIRE_EQUAL(order.size(), 3U);
        BOOST_CHECK(
            order[0] == Scheduler::Priority::TipValidation);
        BOOST_CHECK(
            order[1] == Scheduler::Priority::WinnerReseal);
        BOOST_CHECK(
            order[2] ==
            Scheduler::Priority::SpeculativeValidation);
        BOOST_CHECK(!scheduler.GetStats().active);
    }

    const auto stats{scheduler.GetStats()};
    BOOST_CHECK_EQUAL(stats.requests, rounds * 4);
    BOOST_CHECK_EQUAL(stats.acquisitions, rounds * 4);
    BOOST_CHECK_EQUAL(stats.completions, rounds * 4);
    BOOST_CHECK_EQUAL(stats.release_invariant_violations, 0U);
    BOOST_CHECK_GE(stats.preemption_requests, rounds);
}

BOOST_AUTO_TEST_CASE(
    rc_authenticated_relay_observation_is_staged_and_one_shot)
{
    auto& scheduler{
        matmul::v4::rc::GetRCAcceleratorScheduler()};
    BOOST_REQUIRE(scheduler.ResetStatsForTest());

    auto observation{
        scheduler.BeginAuthenticatedRelayObservation()};
    BOOST_CHECK(
        !scheduler.CommitAuthenticatedRelayObservation(
            observation));
    BOOST_CHECK_EQUAL(
        scheduler.GetStats().authenticated_relay_samples, 0U);

    scheduler.MarkAuthenticatedRelayBodyReceived(observation);
    const auto first_body{observation.body_received};
    BOOST_REQUIRE(first_body);
    scheduler.MarkAuthenticatedRelayBodyReceived(observation);
    BOOST_CHECK(observation.body_received == first_body);
    BOOST_CHECK(
        scheduler.CommitAuthenticatedRelayObservation(
            observation));
    BOOST_CHECK_EQUAL(
        scheduler.GetStats().authenticated_relay_samples, 1U);

    // A duplicate completion cannot count the same authenticated transport
    // interval twice, even if a delivery callback is repeated.
    BOOST_CHECK(
        !scheduler.CommitAuthenticatedRelayObservation(
            observation));
    BOOST_CHECK_EQUAL(
        scheduler.GetStats().authenticated_relay_samples, 1U);

    matmul::v4::rc::RCAcceleratorScheduler::
        AuthenticatedRelayObservation reversed{
            .announced = std::chrono::steady_clock::now(),
            .body_received = std::chrono::steady_clock::now() -
                std::chrono::seconds{1}};
    BOOST_CHECK(
        !scheduler.CommitAuthenticatedRelayObservation(reversed));
    BOOST_CHECK_EQUAL(
        scheduler.GetStats().authenticated_relay_samples, 1U);
}

BOOST_AUTO_TEST_SUITE_END()
