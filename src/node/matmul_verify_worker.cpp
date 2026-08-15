// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/matmul_verify_worker.h>
#include <node/matmul_trusted_attestations.h>

#include <arith_uint256.h>
#include <consensus/params.h>
#include <logging.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_accelerator_scheduler.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <pow.h>
#include <uint256.h>
#include <util/check.h>
#include <util/threadnames.h>

#include <algorithm>
#include <chrono>
#include <iterator>
#include <optional>
#include <thread>
#include <utility>

namespace node {

MatMulVerifyWorker::MatMulVerifyWorker(const Consensus::Params& params, uint32_t max_threads,
                                       std::function<bool(const CBlock&, int32_t, std::optional<int64_t>)> verify_for_test)
    : m_params{params},
      m_verify_override{std::move(verify_for_test)},
      m_max_threads{max_threads > 0
                        ? max_threads
                        : 1}
{
}

MatMulVerifyWorker::~MatMulVerifyWorker()
{
    Stop();
}

MatMulVerifyWorker::EnqueueResult MatMulVerifyWorker::Enqueue(
    Job& job,
    EnqueueMode mode)
{
    Assume((job.block != nullptr) != (job.header != nullptr));
    const uint256 hash{job.GetHeader().GetHash()};
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_stopped) return EnqueueResult::Stopped;
        if (const auto it{m_pending.find(hash)}; it != m_pending.end()) {
            if (mode == EnqueueMode::NewOnly ||
                it->second->job.cancelled->load(std::memory_order_relaxed)) {
                return EnqueueResult::Deferred;
            }
            if (job.block && m_awaiting_quorum.count(hash) != 0) {
                const size_t old_bytes{
                    it->second->job.retained_body_bytes};
                const size_t new_bytes{std::max(
                    old_bytes, job.retained_body_bytes)};
                const size_t additional{new_bytes - old_bytes};
                if (additional >
                    MAX_AWAITING_QUORUM_BYTES -
                        std::min(m_awaiting_quorum_bytes,
                                 MAX_AWAITING_QUORUM_BYTES)) {
                    return EnqueueResult::Deferred;
                }
                m_awaiting_quorum_bytes += additional;
            }
            // A full body arriving behind a header-first job joins the same
            // pure header verdict. Its completion still re-enters ordinary
            // block validation, which alone can authenticate chainwork.
            if (job.completion) {
                it->second->followers.push_back(std::move(job.completion));
            }
            if (job.retryable_failure) {
                it->second->follower_retryable_failures.push_back(
                    std::move(job.retryable_failure));
            }
            if (job.block) {
                it->second->body_joined = true;
                it->second->job.retained_body_bytes =
                    std::max(it->second->job.retained_body_bytes,
                             job.retained_body_bytes);
            }
            if (static_cast<uint8_t>(job.priority) >
                static_cast<uint8_t>(it->second->job.priority)) {
                it->second->job.priority = job.priority;
            }
            job = Job{};
            return EnqueueResult::Joined;
        }
        if (mode == EnqueueMode::JoinOnly) return EnqueueResult::Deferred;
        PruneCancelRetryBackoff();
        if (UnderCancelRetryBackoff(hash)) {
            return EnqueueResult::Deferred;
        }
        if (job.priority == Priority::AuthenticatedTipChild &&
            (!job.cancelled ||
             !job.cancelled->load(std::memory_order_relaxed))) {
            // A valid admission ticket buys a bounded verification attempt,
            // not an uninterruptible claim on the only device submitter.
            // Preempt lower-priority in-flight speculation as soon as an
            // authenticated-tip child arrives. The canceled candidate gets
            // no verdict or peer punishment and remains re-requestable; the
            // queued competing-branch set is retained and its lower priority
            // naturally places it behind the reserved tip lane.
            //
            // Never cancel a body-holding CompetingBranch / AuthenticatedTipChild
            // that is already running ExactReplay. Header-only tip churn was
            // aborting recovery replays, then retryable_failure re-admitted
            // the same hash immediately (live ExactReplay cancelled tight loop).
            //
            // This also interrupts an inline portable device-mismatch retry:
            // ScopedExactReplayCancellation covers the complete predicate,
            // including that retry, and the replay checks cancellation at
            // layer/round command-buffer boundaries.
            for (const auto& [pending_hash, pending] : m_pending) {
                if (pending_hash == hash || !pending->running ||
                    ProtectsBodyReplay(*pending)) {
                    continue;
                }
                const bool lower_priority{
                    static_cast<uint8_t>(pending->job.priority) <
                    static_cast<uint8_t>(
                        Priority::AuthenticatedTipChild)};
                const bool body_preempts_equal_speculation{
                    job.block && pending->job.IsHeaderOnly() &&
                    !pending->body_joined &&
                    pending->job.priority ==
                        Priority::AuthenticatedTipChild};
                if (!lower_priority &&
                    !body_preempts_equal_speculation) {
                    continue;
                }
                pending->job.cancelled->store(
                    true, std::memory_order_relaxed);
            }
        }
        if (!job.cancelled) {
            job.cancelled = std::make_shared<std::atomic_bool>(false);
        }
        auto pending{std::make_shared<Pending>()};
        pending->job = std::move(job);
        // Full-body validation owns acceptance bookkeeping and must never be
        // preempted as header-only speculation.
        pending->body_joined = pending->job.block != nullptr;
        pending->sequence = m_next_sequence++;
        m_queue.push_back(pending);
        m_pending.emplace(hash, pending);
        // Lazily scale the pool: one thread per enqueue until the cap.
        if (m_threads.size() < m_max_threads && m_threads.size() < m_queue.size()) {
            m_threads.emplace_back([this] { WorkerLoop(); });
        }
    }
    m_cv.notify_one();
    return EnqueueResult::Enqueued;
}

MatMulVerifyWorker::HandoffResult
MatMulVerifyWorker::HandoffAuthenticatedTip(Job& replacement)
{
    Assume((replacement.block != nullptr) !=
           (replacement.header != nullptr));
    if (replacement.priority != Priority::AuthenticatedTipChild) {
        return HandoffResult::Deferred;
    }
    const CBlockHeader& replacement_header{replacement.GetHeader()};
    const uint256 replacement_hash{replacement_header.GetHash()};
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_stopped) return HandoffResult::Stopped;
        PruneCancelRetryBackoff();
        if (m_pending.count(replacement_hash) != 0 ||
            UnderCancelRetryBackoff(replacement_hash)) {
            return HandoffResult::Deferred;
        }

        std::shared_ptr<Pending> source;
        for (const auto& [hash, pending] : m_pending) {
            if (hash == replacement_hash ||
                ProtectsBodyReplay(*pending) ||
                !pending->job.IsHeaderOnly() ||
                pending->job.priority !=
                    Priority::AuthenticatedTipChild ||
                !pending->job.equal_priority_handoff_available ||
                !pending->job.rc_pending_lease ||
                pending->job.cancelled->load(
                    std::memory_order_relaxed) ||
                pending->job.height != replacement.height ||
                pending->job.GetHeader().hashPrevBlock !=
                    replacement_header.hashPrevBlock) {
                continue;
            }
            if (!source ||
                pending->sequence < source->sequence) {
                source = pending;
            }
        }
        if (!source) return HandoffResult::Deferred;

        source->job.cancelled->store(
            true, std::memory_order_relaxed);
        source->job.equal_priority_handoff_available = false;
        replacement.rc_pending_lease =
            std::move(source->job.rc_pending_lease);
        if (replacement.IsHeaderOnly()) {
            replacement.rc_speculative_lease =
                std::move(source->job.rc_speculative_lease);
            replacement.retarget_speculative_lease =
                std::move(
                    source->job.retarget_speculative_lease);
            if (replacement.retarget_speculative_lease) {
                replacement.retarget_speculative_lease(
                    replacement_hash);
            }
        } else {
            // A body is no longer speculative. Releasing this ownership
            // decrements the header-only counter and removes the old hash,
            // while the transferred RC pending lease remains held.
            source->job.rc_speculative_lease.reset();
            source->job.retarget_speculative_lease = {};
        }
        replacement.equal_priority_handoff_available = false;
        if (!replacement.cancelled) {
            replacement.cancelled =
                std::make_shared<std::atomic_bool>(false);
        }

        auto next{std::make_shared<Pending>()};
        next->job = std::move(replacement);
        next->body_joined = next->job.block != nullptr;
        next->sequence = m_next_sequence++;
        m_queue.push_back(next);
        m_pending.emplace(replacement_hash, next);

        if (!source->running) {
            std::erase(m_queue, source);
            m_pending.erase(
                source->job.GetHeader().GetHash());
        }
        if (m_threads.size() < m_max_threads &&
            m_threads.size() < m_queue.size()) {
            m_threads.emplace_back([this] { WorkerLoop(); });
        }
    }
    m_cv.notify_one();
    return HandoffResult::HandedOff;
}

void MatMulVerifyWorker::InstallVerifyOverrideForTest(
    std::function<bool(const CBlock&, int32_t, std::optional<int64_t>)> verify)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_verify_override = std::move(verify);
}

bool MatMulVerifyWorker::CanHandoffAuthenticatedTip(
    const CBlockHeader& replacement,
    int32_t height) const
{
    const uint256 replacement_hash{replacement.GetHash()};
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_stopped ||
        m_pending.count(replacement_hash) != 0 ||
        UnderCancelRetryBackoff(replacement_hash)) {
        return false;
    }
    for (const auto& [hash, pending] : m_pending) {
        if (hash != replacement_hash &&
            !ProtectsBodyReplay(*pending) &&
            pending->job.IsHeaderOnly() &&
            pending->job.priority ==
                Priority::AuthenticatedTipChild &&
            pending->job.equal_priority_handoff_available &&
            pending->job.rc_pending_lease &&
            !pending->job.cancelled->load(
                std::memory_order_relaxed) &&
            pending->job.height == height &&
            pending->job.GetHeader().hashPrevBlock ==
                replacement.hashPrevBlock) {
            return true;
        }
    }
    return false;
}

bool MatMulVerifyWorker::Cancel(const uint256& hash)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto it{m_pending.find(hash)};
    if (it == m_pending.end()) return false;
    const auto pending{it->second};
    if (ProtectsBodyReplay(*pending)) return false;
    pending->job.cancelled->store(true, std::memory_order_relaxed);
    if (!pending->running) {
        std::erase(m_queue, pending);
        if (m_awaiting_quorum.erase(hash) != 0) {
            Assume(m_awaiting_quorum_bytes >=
                   pending->job.retained_body_bytes);
            m_awaiting_quorum_bytes -=
                pending->job.retained_body_bytes;
        }
        pending->awaiting_quorum_deadline.reset();
        m_pending.erase(it);
    }
    matmul::v4::rc::GetRCAcceleratorScheduler().NotifyCancellation();
    m_cv.notify_all();
    return true;
}

size_t MatMulVerifyWorker::CancelIf(
    const std::function<bool(const CBlockHeader&, int32_t)>& predicate)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t count{0};
    for (auto it = m_pending.begin(); it != m_pending.end();) {
        const auto pending{it->second};
        if (ProtectsBodyReplay(*pending)) {
            ++it;
            continue;
        }
        if (!predicate(pending->job.GetHeader(), pending->job.height)) {
            ++it;
            continue;
        }
        pending->job.cancelled->store(true, std::memory_order_relaxed);
        ++count;
        if (!pending->running) {
            std::erase(m_queue, pending);
            if (m_awaiting_quorum.erase(it->first) != 0) {
                Assume(m_awaiting_quorum_bytes >=
                       pending->job.retained_body_bytes);
                m_awaiting_quorum_bytes -=
                    pending->job.retained_body_bytes;
            }
            pending->awaiting_quorum_deadline.reset();
            it = m_pending.erase(it);
        } else {
            ++it;
        }
    }
    if (count != 0) {
        matmul::v4::rc::GetRCAcceleratorScheduler().
            NotifyCancellation();
        m_cv.notify_all();
    }
    return count;
}

void MatMulVerifyWorker::CancelAllForTest()
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_shutdown.store(true, std::memory_order_release);
        for (auto& [hash, pending] : m_pending) {
            (void)hash;
            pending->job.cancelled->store(true, std::memory_order_relaxed);
        }
        m_queue.clear();
        for (auto& [hash, pending] : m_awaiting_quorum) {
            (void)hash;
            pending->job.cancelled->store(true, std::memory_order_relaxed);
            pending->awaiting_quorum_deadline.reset();
        }
        m_awaiting_quorum.clear();
        m_awaiting_quorum_bytes = 0;
        m_cancel_retry_backoff.clear();
    }
    matmul::v4::rc::GetRCAcceleratorScheduler().NotifyCancellation();
    m_cv.notify_all();
    const auto deadline{
        std::chrono::steady_clock::now() + std::chrono::seconds{2}};
    for (;;) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            bool running{false};
            for (const auto& [hash, pending] : m_pending) {
                (void)hash;
                if (pending->running) {
                    running = true;
                    break;
                }
            }
            if (!running) {
                m_pending.clear();
                break;
            }
        }
        if (std::chrono::steady_clock::now() >= deadline) break;
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    m_shutdown.store(false, std::memory_order_release);
}

bool MatMulVerifyWorker::Contains(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pending.count(hash) != 0;
}

void MatMulVerifyWorker::SetActiveTip(const uint256& tip_hash,
                                      int32_t tip_height)
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_tip_hash = tip_hash;
        m_tip_height = tip_height;
    }
    // Tip movement can change which parked/queued job should run next.
    m_cv.notify_all();
}

void MatMulVerifyWorker::SetCappedAuthorityFrontier(
    std::optional<int32_t> height)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_capped_authority_frontier = height;
}

void MatMulVerifyWorker::NotifyQuorumReady(const uint256& hash)
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it{m_awaiting_quorum.find(hash)};
        if (it == m_awaiting_quorum.end()) return;
        auto pending{it->second};
        m_awaiting_quorum.erase(it);
        Assume(m_awaiting_quorum_bytes >=
               pending->job.retained_body_bytes);
        m_awaiting_quorum_bytes -= pending->job.retained_body_bytes;
        pending->awaiting_quorum_deadline.reset();
        if (!pending->running &&
            std::find(m_queue.begin(), m_queue.end(), pending) ==
                m_queue.end()) {
            m_queue.push_back(std::move(pending));
        }
    }
    m_cv.notify_one();
}

void MatMulVerifyWorker::Stop()
{
    std::vector<std::shared_ptr<Pending>> orphaned;
    std::vector<std::thread> threads;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stopped = true;
        m_shutdown.store(true, std::memory_order_release);
        // Cancel running ExactReplay as well as queued/parked work. CPU
        // auto-fallback (and a spinning b-mmverify) otherwise holds
        // b-shutoff in join() until the current episode finishes — SIGTERM
        // then looks hung, operators SIGKILL, and that unclean stop bricks
        // assumeutxo shielded_state.
        for (auto& [hash, pending] : m_pending) {
            (void)hash;
            pending->job.cancelled->store(true, std::memory_order_relaxed);
        }
        // Queued-not-started and parked-awaiting jobs receive no consensus
        // completion. Their retryable-failure cleanup runs below so network
        // async markers are released while the unprocessed blocks stay
        // re-requestable.
        orphaned.swap(m_queue);
        for (auto& [hash, pending] : m_awaiting_quorum) {
            (void)hash;
            orphaned.push_back(pending);
        }
        m_awaiting_quorum.clear();
        m_awaiting_quorum_bytes = 0;
        for (const auto& pending : orphaned) {
            pending->job.cancelled->store(true, std::memory_order_relaxed);
            pending->awaiting_quorum_deadline.reset();
            m_pending.erase(pending->job.GetHeader().GetHash());
        }
        threads.swap(m_threads);
        m_cancel_retry_backoff.clear();
    }
    m_cv.notify_all();
    matmul::v4::rc::GetRCAcceleratorScheduler().NotifyCancellation();
    for (std::thread& t : threads) {
        if (t.joinable()) t.join();
    }
    for (auto& pending : orphaned) {
        if (pending->job.retryable_failure) {
            pending->job.retryable_failure();
        }
        for (auto& retryable_failure :
             pending->follower_retryable_failures) {
            retryable_failure();
        }
    }
    // `orphaned` destroyed here, after the in-flight jobs joined.
}

size_t MatMulVerifyWorker::QueueDepthForTest() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_queue.size();
}

size_t MatMulVerifyWorker::AwaitingQuorumForTest() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_awaiting_quorum.size();
}

bool MatMulVerifyWorker::CancelRetryBackoffActiveForTest(
    const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return UnderCancelRetryBackoff(hash);
}

bool MatMulVerifyWorker::ProtectsBodyReplay(const Pending& pending)
{
    // Full-body validation owns acceptance bookkeeping. Header-only
    // speculation may be revoked; a body-holding ExactReplay may not.
    return pending.body_joined;
}

void MatMulVerifyWorker::ArmCancelRetryBackoff(const uint256& hash)
{
    auto& entry{m_cancel_retry_backoff[hash]};
    entry.consecutive =
        std::min(entry.consecutive + 1, CANCEL_RETRY_BACKOFF_MAX_EXP);
    const auto delay{
        CANCEL_RETRY_BACKOFF_BASE *
        (1 << std::max(0, entry.consecutive - 1))};
    entry.not_before = std::chrono::steady_clock::now() + delay;
    LogDebug(
        BCLog::NET,
        "matmul verify worker cancel retry backoff: block=%s "
        "consecutive=%d delay=%ds\n",
        hash.ToString(), entry.consecutive,
        static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(
                             delay)
                             .count()));
}

bool MatMulVerifyWorker::UnderCancelRetryBackoff(const uint256& hash) const
{
    const auto it{m_cancel_retry_backoff.find(hash)};
    if (it == m_cancel_retry_backoff.end()) return false;
    return std::chrono::steady_clock::now() < it->second.not_before;
}

void MatMulVerifyWorker::ClearCancelRetryBackoff(const uint256& hash)
{
    m_cancel_retry_backoff.erase(hash);
}

void MatMulVerifyWorker::PruneCancelRetryBackoff()
{
    const auto now{std::chrono::steady_clock::now()};
    const auto stale_after{
        CANCEL_RETRY_BACKOFF_BASE *
        (1 << (CANCEL_RETRY_BACKOFF_MAX_EXP - 1))};
    for (auto it = m_cancel_retry_backoff.begin();
         it != m_cancel_retry_backoff.end();) {
        if (now >= it->second.not_before + stale_after) {
            it = m_cancel_retry_backoff.erase(it);
        } else {
            ++it;
        }
    }
}

bool MatMulVerifyWorker::HigherPriority(const Pending& lhs,
                                        const Pending& rhs) const
{
    const auto left{node::matmul_trusted::MakeTrustedWorkRank(
        lhs.job.GetHeader().hashPrevBlock == m_tip_hash,
        lhs.job.height,
        m_tip_height,
        static_cast<uint8_t>(lhs.job.priority),
        lhs.sequence)};
    const auto right{node::matmul_trusted::MakeTrustedWorkRank(
        rhs.job.GetHeader().hashPrevBlock == m_tip_hash,
        rhs.job.height,
        m_tip_height,
        static_cast<uint8_t>(rhs.job.priority),
        rhs.sequence)};
    return node::matmul_trusted::PreferTrustedWork(left, right);
}

void MatMulVerifyWorker::TakeExpiredAwaitingQuorum(
    std::vector<std::shared_ptr<Pending>>& expired)
{
    const auto now{std::chrono::steady_clock::now()};
    for (auto it = m_awaiting_quorum.begin();
         it != m_awaiting_quorum.end();) {
        auto& pending{it->second};
        const bool cancelled{
            pending->job.cancelled->load(std::memory_order_relaxed)};
        const bool timed_out{
            pending->awaiting_quorum_deadline.has_value() &&
            now >= *pending->awaiting_quorum_deadline};
        if (!cancelled && !timed_out) {
            ++it;
            continue;
        }
        pending->awaiting_quorum_deadline.reset();
        m_pending.erase(it->first);
        Assume(m_awaiting_quorum_bytes >=
               pending->job.retained_body_bytes);
        m_awaiting_quorum_bytes -= pending->job.retained_body_bytes;
        expired.push_back(pending);
        it = m_awaiting_quorum.erase(it);
    }
}

std::optional<std::chrono::steady_clock::time_point>
MatMulVerifyWorker::NextAwaitingDeadline() const
{
    std::optional<std::chrono::steady_clock::time_point> next;
    for (const auto& [hash, pending] : m_awaiting_quorum) {
        (void)hash;
        if (!pending->awaiting_quorum_deadline) continue;
        if (!next || *pending->awaiting_quorum_deadline < *next) {
            next = pending->awaiting_quorum_deadline;
        }
    }
    return next;
}

void MatMulVerifyWorker::FinishRetryablePending(
    const std::shared_ptr<Pending>& pending)
{
    std::vector<std::function<void()>> callbacks;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ArmCancelRetryBackoff(pending->job.GetHeader().GetHash());
        if (pending->job.retryable_failure) {
            callbacks.push_back(std::move(pending->job.retryable_failure));
        }
        std::move(pending->follower_retryable_failures.begin(),
                  pending->follower_retryable_failures.end(),
                  std::back_inserter(callbacks));
    }
    for (auto& callback : callbacks) callback();
}

void MatMulVerifyWorker::WorkerLoop()
{
    util::ThreadRename("mmverify");
    for (;;) {
        std::shared_ptr<Pending> pending;
        std::vector<std::shared_ptr<Pending>> expired_awaiting;
        uint256 active_tip_hash{};
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            for (;;) {
                TakeExpiredAwaitingQuorum(expired_awaiting);
                if (!expired_awaiting.empty()) break;
                if (m_stopped) return;
                if (!m_queue.empty()) break;
                const auto deadline{NextAwaitingDeadline()};
                if (deadline) {
                    m_cv.wait_until(lock, *deadline);
                } else {
                    m_cv.wait(lock, [this] {
                        return m_stopped || !m_queue.empty() ||
                               !m_awaiting_quorum.empty();
                    });
                }
            }
            if (m_stopped && m_queue.empty() && expired_awaiting.empty()) {
                // Stop() owns cleanup of any remaining parked jobs.
                return;
            }
        }
        for (auto& expired : expired_awaiting) {
            LogWarning(
                "matmul trusted mirror deferred: block=%s height=%d "
                "result=%s (retryable, peer not punished)\n",
                expired->job.GetHeader().GetHash().ToString(),
                expired->job.height,
                matmul::trusted::WaitResultName(
                    expired->job.cancelled->load(
                        std::memory_order_relaxed)
                        ? matmul::trusted::WaitResult::Cancelled
                        : matmul::trusted::WaitResult::Timeout));
            FinishRetryablePending(expired);
        }
        if (!expired_awaiting.empty() || m_stopped) {
            if (m_stopped) return;
            continue;
        }

        std::function<bool(const CBlock&, int32_t, std::optional<int64_t>)> verify_override;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            if (m_stopped) return;
            if (m_queue.empty()) continue;
            size_t best{0};
            for (size_t i = 1; i < m_queue.size(); ++i) {
                if (HigherPriority(*m_queue[i], *m_queue[best])) best = i;
            }
            pending = m_queue[best];
            m_queue.erase(m_queue.begin() + best);
            pending->running = true;
            active_tip_hash = m_tip_hash;
            verify_override = m_verify_override;
        }

        Job& job{pending->job};
        const CBlockHeader& header{job.GetHeader()};
        const uint256 hash{header.GetHash()};
        const bool tip_extending{header.hashPrevBlock == active_tip_hash};
        if (job.on_started) job.on_started();
        const auto finish_retryable_without_verdict = [&] {
            std::vector<std::function<void()>> callbacks;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                ArmCancelRetryBackoff(hash);
                if (job.retryable_failure) {
                    callbacks.push_back(
                        std::move(job.retryable_failure));
                }
                std::move(
                    pending->follower_retryable_failures.begin(),
                    pending->follower_retryable_failures.end(),
                    std::back_inserter(callbacks));
                // Move every callback while `pending` is unquestionably still
                // registered, then erase ownership. The local shared_ptr also
                // keeps the object alive through callback invocation.
                m_pending.erase(hash);
                m_awaiting_quorum.erase(hash);
            }
            for (auto& callback : callbacks) callback();
        };
        bool ok{false};
        bool local_execution_failure{false};
        const bool shutting_down{
            m_shutdown.load(std::memory_order_acquire)};
        if (job.cancelled->load(std::memory_order_relaxed) &&
            (!ProtectsBodyReplay(*pending) || shutting_down)) {
            finish_retryable_without_verdict();
            continue;
        }
        matmul::v4::rc::RCAcceleratorScheduler::Lease
            accelerator_lease;
        const bool trusted_exact_replay{
            !verify_override &&
            node::matmul_trusted::IsTrustedMirror() &&
            m_params.IsMatMulTrustedReplayAttestationActive(job.height)};
        const bool protect_body_replay{ProtectsBodyReplay(*pending)};
        if (!verify_override &&
            m_params.IsMatMulRCFamilyActive(job.height) &&
            !trusted_exact_replay) {
            // CompetingBranch must use TipValidation, not SpeculativeValidation.
            // Field report (Wizard Partners, 2026-08-10): async ExactReplay of a
            // non-active/canonical competing branch at SpeculativeValidation was
            // preempted ("ExactReplay: cancelled", outcome=3) and the node never
            // connected that branch — the "zombie block" freeze. Operators worked
            // around it with matmulrcexecution=strict-device (sync path). Elevating
            // CompetingBranch to TipValidation keeps async verify from being
            // starved by CandidateMining while still ranking below an authenticated
            // tip-child via the worker's own Priority ordering.
            // Configured nodes must not map *any* async worker job onto
            // TipValidation: AuthenticatedTipChild is every `pprev==tip`
            // sibling at an unattested racing tip, so 69–198 same-height
            // bodies occupied both GPU slots and starved CandidateMining /
            // submitblock ExactReplay (win-rate, not log noise). P2P
            // admission already skips GPU; this mapping is belt-and-suspenders
            // if a job leaks through. Unconfigured nodes keep the historical
            // CompetingBranch→TipValidation mapping (zombie freeze workaround).
            const auto device_priority{[&] {
                using AccelPriority =
                    matmul::v4::rc::RCAcceleratorScheduler::Priority;
                if (!node::matmul_trusted::IsConfigured()) {
                    return (job.priority == Priority::AuthenticatedTipChild ||
                            job.priority == Priority::CompetingBranch)
                               ? AccelPriority::TipValidation
                               : AccelPriority::SpeculativeValidation;
                }
                // Configured nodes must not map *every* pprev==tip sibling
                // onto TipValidation (69–198 unattested bodies starved
                // CandidateMining). Unique attested catch-up must: live
                // 2026-08-15 the signer sat on an attested tip while
                // CandidateMining held the device and tip_validation stayed 0.
                if (node::matmul_trusted::HasQuorum(hash, job.height) &&
                    (job.priority == Priority::AuthenticatedTipChild ||
                     job.priority == Priority::CompetingBranch)) {
                    return AccelPriority::TipValidation;
                }
                return AccelPriority::SpeculativeValidation;
            }()};
            const auto episode_params{
                matmul::v4::rc::ResolveRCEpisodeParams(
                    m_params, job.height)};
            const uint64_t workspace_bytes{
                matmul::v4::rc::
                    EstimateRCExactReplayWorkspaceBytes(
                        episode_params)};
            // Body-holding recovery replay: the scheduler must not raise the
            // job latch, or ExactReplay cancels and retryable_failure
            // immediately re-admits the same hash. Header-only speculation
            // still yields the device via preempt_latch.
            accelerator_lease =
                matmul::v4::rc::GetRCAcceleratorScheduler().Acquire(
                    device_priority,
                    (protect_body_replay && !shutting_down)
                        ? nullptr
                        : job.cancelled.get(),
                    strprintf("verify:%s:%d", hash.ToString(),
                              job.height),
                    /*external_cancelled=*/nullptr,
                    matmul::v4::rc::RCAcceleratorScheduler::
                        DEFAULT_MAX_QUEUE_WAIT,
                    workspace_bytes);
            if (!accelerator_lease) {
                // A scheduler cancellation is a local retryable outcome, not
                // a consensus verdict. Run the same delivery-marker/source
                // cleanup as an in-replay accelerator cancellation.
                finish_retryable_without_verdict();
                continue;
            }
            LogDebug(
                BCLog::NET,
                "matmul RC accelerator acquired: block=%s height=%d "
                "priority=%s queue_wait=%.6fs\n",
                hash.ToString(), job.height,
                matmul::v4::rc::ToString(
                    accelerator_lease.GetPriority()),
                accelerator_lease.QueueWaitSeconds());
        }
        matmul::v4::rc::ScopedExactReplayCancellation cancellation_scope{
            (protect_body_replay && !shutting_down) ? nullptr
                                                   : job.cancelled.get()};
        if (verify_override) {
            if (job.block) {
                ok = verify_override(
                    *job.block, job.height, job.parent_median_time_past);
            } else {
                CBlock synthetic{header};
                ok = verify_override(
                    synthetic, job.height, job.parent_median_time_past);
            }
        } else if (trusted_exact_replay) {
            // Never block a worker thread on attestation quorum. Park the job
            // (deadline = matmultrustedwaitms) so other blocks stay in flight;
            // NotifyQuorumReady requeues when M-of-N arrives. Timeout/cancel
            // remain retryable and non-punitive.
            //
            // Do not park provably-unattestable work: heights above the known
            // attested high-water (except the tip-extender, which may probe one
            // step ahead) must not consume scarce park slots. Peer-tip hints
            // are unauthenticated competing headers and must not inflate this
            // bound (live: frontier 187859 vs signer 187791). Use the same
            // capped frontier admit uses, not raw HighestAttestedHeight().
            std::optional<int32_t> frontier;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                frontier = m_capped_authority_frontier;
            }
            if (!frontier.has_value()) {
                frontier = node::matmul_trusted::HighestAttestedHeight();
            }
            if (!tip_extending && frontier.has_value() &&
                job.height > *frontier) {
                LogDebug(
                    BCLog::NET,
                    "matmul trusted mirror skip park above frontier: "
                    "block=%s height=%d frontier=%d\n",
                    hash.ToString(), job.height, *frontier);
                finish_retryable_without_verdict();
                continue;
            }
            if (node::matmul_trusted::HasQuorum(hash, job.height)) {
                ok = true;
                // Ephemeral only. The index's trusted-status bit is audit
                // metadata and must never survive config rotation as
                // authority; every restart rebuilds this memo from signatures
                // verified against the current signer set and threshold.
                CacheMatMulEncDrVerdict(hash, true);
                LogPrintf(
                    "matmul trusted mirror quorum accepted: block=%s "
                    "height=%d threshold=%u\n",
                    hash.ToString(), job.height,
                    node::matmul_trusted::Threshold());
            } else {
                const auto deadline{
                    std::chrono::steady_clock::now() +
                    node::matmul_trusted::WaitTimeout()};
                // Waiting for signatures is not expensive replay work. Drop
                // the pending-work lease before publishing this job in the
                // parked set, otherwise the production default cap of one
                // prevents every later body from reaching quorum admission.
                // The parked set has its own count/byte bounds below.
                if (job.on_parked) job.on_parked();
                job.rc_pending_lease.reset();
                bool parked{false};
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    const bool count_available{
                        m_awaiting_quorum.size() <
                        MAX_AWAITING_QUORUM_JOBS};
                    const bool bytes_available{
                        job.retained_body_bytes <=
                        MAX_AWAITING_QUORUM_BYTES -
                            std::min(m_awaiting_quorum_bytes,
                                     MAX_AWAITING_QUORUM_BYTES)};
                    if (count_available && bytes_available) {
                        pending->running = false;
                        pending->awaiting_quorum_deadline = deadline;
                        m_awaiting_quorum[hash] = pending;
                        m_awaiting_quorum_bytes +=
                            job.retained_body_bytes;
                        parked = true;
                    }
                }
                if (!parked) {
                    LogWarning(
                        "matmul trusted mirror deferred: block=%s height=%d "
                        "result=awaiting_quorum_capacity (retryable, peer not punished)\n",
                        hash.ToString(), job.height);
                    finish_retryable_without_verdict();
                    continue;
                }
                // TOCTOU: quorum may have landed between HasQuorum and park.
                if (node::matmul_trusted::HasQuorum(hash, job.height)) {
                    NotifyQuorumReady(hash);
                } else {
                    m_cv.notify_one();
                }
                continue;
            }
        } else {
            // A Stage-3 attachment is block-body data and is deliberately not
            // committed by CBlockHeader::GetHash(). Therefore neither the
            // header-keyed legacy single-flight nor its verdict memo may wrap
            // this path: two deliveries can share a header while carrying
            // different proof bodies. VerifyRCStage3ConsensusAttachment owns
            // the proof-aware (header, registry, payload) cache/single-flight.
            if constexpr (
                matmul::v4::rc::kRCStage3SuccinctAuthorityReady) {
                if (job.block && m_params.IsMatMulRCFamilyActive(job.height)) {
                    const auto target =
                        DeriveTarget(header.nBits, m_params.powLimit);
                    ok = target.has_value() &&
                         matmul::v4::rc::VerifyRCStage3ConsensusAttachment(
                             *job.block, m_params, job.height,
                             ArithToUint256(*target), nullptr) ==
                             matmul::v4::rc::RCStage3AttachmentStatus::Valid;
                    LogDebug(BCLog::NET,
                             "matmul async Stage-3 verify: block %s height %d ok=%d\n",
                             hash.ToString(), job.height, ok);
                    goto complete;
                }
            }

            bool carrier_missing{false};
            const auto verify_pure = [&]() {
                if (m_params.IsMatMulRCCoupledActive(
                        job.height)) {
                    return CheckMatMulProofOfWork_RCCoupled(
                        header, m_params, job.height);
                }
                if (m_params.IsMatMulRCActive(job.height)) {
                    std::string detail;
                    const auto outcome{
                        CheckMatMulProofOfWork_RCOutcome(
                            header, m_params, job.height,
                            &carrier_missing, &detail)};
                    local_execution_failure =
                        outcome ==
                            MatMulRCValidationOutcome::
                                LOCAL_ACCELERATOR_FAILURE ||
                        outcome ==
                            MatMulRCValidationOutcome::CANCELLED;
                    if (local_execution_failure) {
                        LogWarning(
                            "matmul async RC replay deferred: block=%s height=%d outcome=%d detail=%s\n",
                            hash.ToString(), job.height,
                            static_cast<int>(outcome), detail);
                    }
                    return outcome ==
                        MatMulRCValidationOutcome::VALID;
                }
                if (!job.block) return false;
                return CheckMatMulProofOfWork_V4EncDr(
                    *job.block, m_params, job.height,
                    job.parent_median_time_past);
            };
            // Single-flight wiring (H5 primitive): duplicate deliveries of the
            // same hash across worker threads collapse to ONE recompute; the
            // followers reuse the leader's verdict (pure function of the
            // header + parent MTP). NOTE for WP-9: this wraps the WHOLE
            // predicate from the worker; when WP-9 wires the same primitive
            // INSIDE the pow.cpp recompute branch for the remaining
            // synchronous callers, drop this outer wrap (one-line change) so
            // the guard is not taken re-entrantly with two different scopes.
            // Datacenter profile-2: a false verdict caused solely by a
            // not-yet-arrived sampled carrier is a transient availability
            // miss and must not poison the header verdict memo.
            MatMulRecomputeSingleFlight sf(hash);
            const auto suppress_verdict{[&] {
                return local_execution_failure ||
                       (job.cancelled->load(std::memory_order_relaxed) &&
                        (!ProtectsBodyReplay(*pending) || shutting_down));
            }};
            if (sf.IsLeader()) {
                ok = verify_pure();
                // Cancellation means no verdict. Publishing the cancellation
                // result would poison followers and the persistent header
                // memo, especially when a valid replay reports false solely
                // because the cancellation boundary fired. A body-holding
                // replay that finished is a real verdict even if a later
                // header-only tip child raised the latch.
                if (!suppress_verdict()) {
                    sf.SetResult(ok); // publish before ~sf releases waiters
                }
            } else if (const auto leader_result{sf.LeaderResult()}) {
                ok = *leader_result; // sketch already Put() on an accepted block
            } else {
                // Leader exited without publishing: decide ourselves.
                ok = verify_pure();
            }
            if (!suppress_verdict() && !(carrier_missing && !ok)) {
                CacheMatMulEncDrVerdict(hash, ok);
            }
            LogDebug(BCLog::NET, "matmul async verify: block %s height %d encdr_ok=%d carrier_missing=%d local_failure=%d\n",
                     hash.ToString(), job.height, ok, carrier_missing,
                     local_execution_failure);
        }
complete:
        std::vector<std::function<void(bool)>> completions;
        std::vector<std::function<void()>> retryable_failures;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_pending.erase(hash);
            const bool cancelled_header_only{
                job.cancelled->load(std::memory_order_relaxed) &&
                (!ProtectsBodyReplay(*pending) ||
                 (m_shutdown.load(std::memory_order_acquire) && !ok))};
            const bool retryable_without_verdict{
                local_execution_failure || cancelled_header_only};
            if (retryable_without_verdict) {
                ArmCancelRetryBackoff(hash);
                if (job.retryable_failure) {
                    retryable_failures.push_back(
                        std::move(job.retryable_failure));
                }
                std::move(
                    pending->follower_retryable_failures.begin(),
                    pending->follower_retryable_failures.end(),
                    std::back_inserter(retryable_failures));
            } else if (!cancelled_header_only) {
                ClearCancelRetryBackoff(hash);
                if (job.completion) {
                    completions.push_back(std::move(job.completion));
                }
                std::move(pending->followers.begin(),
                          pending->followers.end(),
                          std::back_inserter(completions));
            }
        }
        for (auto& retryable_failure : retryable_failures) {
            retryable_failure();
        }
        for (auto& completion : completions) completion(ok);
    }
}

} // namespace node
