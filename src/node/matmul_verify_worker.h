// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MATMUL_VERIFY_WORKER_H
#define BITCOIN_NODE_MATMUL_VERIFY_WORKER_H

#include <primitives/block.h>

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace Consensus {
struct Params;
} // namespace Consensus

namespace node {

/** WP-7 / C5: bounded off-thread worker pool for the v4.4 ENC-DR O(W)
 *  reference recompute.
 *
 *  The single net message-handler thread holds g_msgproc_mutex across
 *  ProcessMessages -> ProcessBlock -> ... -> the ENC-DR recompute; cs_main is
 *  released around the recompute but g_msgproc_mutex is not, so every other
 *  peer's messages queue behind seconds of GEMM per non-cached block. This
 *  worker takes the PURE part of that work off the message thread:
 *
 *   - A Job carries the block, its resolved height (= prev->nHeight + 1,
 *     resolved by the dispatcher under cs_main) and a completion closure.
 *   - The worker computes only the pure predicate
 *     CheckMatMulProofOfWork_V4EncDr (never touching cs_main or
 *     g_msgproc_mutex), under the process-wide MatMulRecomputeSingleFlight
 *     leader/follower guard so duplicate deliveries of one hash collapse to a
 *     single recompute, then memoizes the verdict via CacheMatMulEncDrVerdict.
 *   - The completion (still on the worker thread) re-enters the ordinary
 *     acceptance machinery (ProcessNewBlock); the validation.cpp ENC-DR seam
 *     short-circuits on the memoized verdict, so the expensive step is not
 *     repeated.
 *
 *  Queue depth needs no separate bound: every enqueued job's closure owns a
 *  ScopedMatMulPendingVerification slot, so depth is bounded by
 *  nMatMulMaxPendingVerifications by construction.
 *
 *  INACTIVITY INVARIANT: net_processing constructs this object only when
 *  nMatMulV4Height != INT32_MAX (and -matmulasyncverify is not disabled); with
 *  the fork disabled no instance ever exists and no thread is ever spawned. */
class MatMulVerifyWorker
{
public:
    struct Job {
        std::shared_ptr<const CBlock> block;
        //! Height the block validates at (= prev->nHeight + 1), resolved by the
        //! dispatcher under cs_main before enqueueing.
        int32_t height{0};
        //! Runs on the worker thread after the verdict is memoized. May be
        //! empty. NOT run for jobs still queued when Stop() destroys the queue
        //! (their captured RAII state releases resources on destruction).
        std::function<void(bool encdr_ok)> completion;
    };

    /** @param[in] params       Consensus params (must outlive this object).
     *  @param[in] max_threads  Worker pool size; 0 = auto
     *                          (hardware_concurrency()/2 clamped to
     *                          [1, nMatMulMaxPendingVerifications]).
     *  @param[in] verify_for_test  Test-only seam replacing the pure predicate
     *                          (skips single-flight + verdict memo). */
    explicit MatMulVerifyWorker(const Consensus::Params& params, uint32_t max_threads = 0,
                                std::function<bool(const CBlock&, int32_t)> verify_for_test = nullptr);
    ~MatMulVerifyWorker(); // Stop() + join

    /** Try to enqueue a job. On success the job is moved-from and true is
     *  returned. On failure (worker stopped) the job is LEFT INTACT and false
     *  is returned — the caller must fall back to the synchronous path (e.g.
     *  by invoking the completion itself). Threads are started lazily. */
    bool Enqueue(Job& job);

    /** Stop accepting jobs; DESTROY queued-not-started jobs WITHOUT running
     *  their completions (RAII captured inside the closures releases slots);
     *  join in-flight jobs. Idempotent. */
    void Stop();

    //! Test introspection: current queued (not yet started) job count.
    size_t QueueDepthForTest() const;

private:
    void WorkerLoop();

    const Consensus::Params& m_params;
    const std::function<bool(const CBlock&, int32_t)> m_verify_override;
    const uint32_t m_max_threads;

    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<Job> m_queue;             // GUARDED_BY(m_mutex)
    bool m_stopped{false};               // GUARDED_BY(m_mutex)
    std::vector<std::thread> m_threads;  // GUARDED_BY(m_mutex); lazily started on Enqueue
};

} // namespace node

#endif // BITCOIN_NODE_MATMUL_VERIFY_WORKER_H
