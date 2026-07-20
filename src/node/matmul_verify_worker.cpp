// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/matmul_verify_worker.h>

#include <consensus/params.h>
#include <logging.h>
#include <pow.h>
#include <uint256.h>
#include <util/check.h>
#include <util/threadnames.h>

#include <algorithm>
#include <utility>

namespace node {
namespace {
//! Upper bound for the async queue / pool size. LT/RC tip-verify may use a
//! tighter pending cap, but the worker may see mixed heights; take the max so
//! the Assume never false-fires when the looser (non-LT) cap is in force.
uint32_t MaxPendingCap(const Consensus::Params& params)
{
    return std::max({params.nMatMulMaxPendingVerifications, params.nMatMulLTMaxPendingVerifications,
                     params.nMatMulRCMaxPendingVerifications});
}
} // namespace

MatMulVerifyWorker::MatMulVerifyWorker(const Consensus::Params& params, uint32_t max_threads,
                                       std::function<bool(const CBlock&, int32_t, std::optional<int64_t>)> verify_for_test)
    : m_params{params},
      m_verify_override{std::move(verify_for_test)},
      m_max_threads{max_threads > 0
                        ? max_threads
                        : std::clamp<uint32_t>(std::thread::hardware_concurrency() / 2, 1,
                                               std::max<uint32_t>(1, MaxPendingCap(params)))}
{
}

MatMulVerifyWorker::~MatMulVerifyWorker()
{
    Stop();
}

bool MatMulVerifyWorker::Enqueue(Job& job)
{
    Assume(job.block != nullptr);
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_stopped) return false;
        m_queue.push_back(std::move(job));
        // Depth is bounded by the pending-verification slot cap by construction
        // (every job's closure owns a slot); flag a violation in debug builds.
        Assume(m_queue.size() <= std::max<uint32_t>(1, MaxPendingCap(m_params)));
        // Lazily scale the pool: one thread per enqueue until the cap.
        if (m_threads.size() < m_max_threads && m_threads.size() < m_queue.size()) {
            m_threads.emplace_back([this] { WorkerLoop(); });
        }
    }
    m_cv.notify_one();
    return true;
}

void MatMulVerifyWorker::Stop()
{
    std::deque<Job> orphaned;
    std::vector<std::thread> threads;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stopped = true;
        // Queued-not-started jobs are destroyed WITHOUT running their
        // completions: the RAII state captured in the closures (verification
        // slots) is released by destruction, and the un-processed blocks stay
        // re-requestable — the same semantics as the existing global-budget
        // "defer" path.
        orphaned.swap(m_queue);
        threads.swap(m_threads);
    }
    m_cv.notify_all();
    for (std::thread& t : threads) {
        if (t.joinable()) t.join();
    }
    // `orphaned` destroyed here, after the in-flight jobs joined.
}

size_t MatMulVerifyWorker::QueueDepthForTest() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_queue.size();
}

void MatMulVerifyWorker::WorkerLoop()
{
    util::ThreadRename("mmverify");
    for (;;) {
        Job job;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this]() { return m_stopped || !m_queue.empty(); });
            if (m_stopped) return; // remaining queued jobs are drained by Stop()
            job = std::move(m_queue.front());
            m_queue.pop_front();
        }

        const uint256 hash{job.block->GetHash()};
        bool ok;
        if (m_verify_override) {
            ok = m_verify_override(*job.block, job.height, job.parent_median_time_past);
        } else {
            // Single-flight wiring (H5 primitive): duplicate deliveries of the
            // same hash across worker threads collapse to ONE recompute; the
            // followers reuse the leader's verdict (pure function of the
            // header + parent MTP). NOTE for WP-9: this wraps the WHOLE
            // predicate from the worker; when WP-9 wires the same primitive
            // INSIDE the pow.cpp recompute branch for the remaining
            // synchronous callers, drop this outer wrap (one-line change) so
            // the guard is not taken re-entrantly with two different scopes.
            MatMulRecomputeSingleFlight sf(hash);
            if (sf.IsLeader()) {
                if (m_params.IsMatMulRCActive(job.height)) {
                    ok = CheckMatMulProofOfWork_RC(*job.block, m_params, job.height);
                } else {
                    ok = CheckMatMulProofOfWork_V4EncDr(*job.block, m_params, job.height,
                                                        job.parent_median_time_past);
                }
                sf.SetResult(ok); // publish before ~sf releases waiters
            } else if (const auto leader_result{sf.LeaderResult()}) {
                ok = *leader_result; // sketch already Put() on an accepted block
            } else {
                // Leader exited without publishing: decide ourselves.
                if (m_params.IsMatMulRCActive(job.height)) {
                    ok = CheckMatMulProofOfWork_RC(*job.block, m_params, job.height);
                } else {
                    ok = CheckMatMulProofOfWork_V4EncDr(*job.block, m_params, job.height,
                                                        job.parent_median_time_past);
                }
            }
            CacheMatMulEncDrVerdict(hash, ok);
            LogDebug(BCLog::NET, "matmul async verify: block %s height %d encdr_ok=%d\n",
                     hash.ToString(), job.height, ok);
        }
        if (job.completion) job.completion(ok);
    }
}

} // namespace node
