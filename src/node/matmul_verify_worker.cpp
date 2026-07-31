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
#include <iterator>
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
            }
            if (static_cast<uint8_t>(job.priority) >
                static_cast<uint8_t>(it->second->job.priority)) {
                it->second->job.priority = job.priority;
            }
            job = Job{};
            return EnqueueResult::Joined;
        }
        if (mode == EnqueueMode::JoinOnly) return EnqueueResult::Deferred;
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
            // This also interrupts an inline portable device-mismatch retry:
            // ScopedExactReplayCancellation covers the complete predicate,
            // including that retry, and the replay checks cancellation at
            // layer/round command-buffer boundaries.
            for (const auto& [pending_hash, pending] : m_pending) {
                if (pending_hash == hash || !pending->running ||
                    pending->body_joined) {
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
        if (m_pending.count(replacement_hash) != 0) {
            return HandoffResult::Deferred;
        }

        std::shared_ptr<Pending> source;
        for (const auto& [hash, pending] : m_pending) {
            if (hash == replacement_hash ||
                pending->body_joined ||
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

bool MatMulVerifyWorker::CanHandoffAuthenticatedTip(
    const CBlockHeader& replacement,
    int32_t height) const
{
    const uint256 replacement_hash{replacement.GetHash()};
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_stopped ||
        m_pending.count(replacement_hash) != 0) {
        return false;
    }
    for (const auto& [hash, pending] : m_pending) {
        if (hash != replacement_hash &&
            !pending->body_joined &&
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
    if (pending->body_joined) return false;
    pending->job.cancelled->store(true, std::memory_order_relaxed);
    if (!pending->running) {
        std::erase(m_queue, pending);
        m_pending.erase(it);
    }
    matmul::v4::rc::GetRCAcceleratorScheduler().NotifyCancellation();
    return true;
}

size_t MatMulVerifyWorker::CancelIf(
    const std::function<bool(const CBlockHeader&, int32_t)>& predicate)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t count{0};
    for (auto it = m_pending.begin(); it != m_pending.end();) {
        const auto pending{it->second};
        if (pending->body_joined) {
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
            it = m_pending.erase(it);
        } else {
            ++it;
        }
    }
    if (count != 0) {
        matmul::v4::rc::GetRCAcceleratorScheduler().
            NotifyCancellation();
    }
    return count;
}

bool MatMulVerifyWorker::Contains(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pending.count(hash) != 0;
}

void MatMulVerifyWorker::Stop()
{
    std::vector<std::shared_ptr<Pending>> orphaned;
    std::vector<std::thread> threads;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stopped = true;
        // Queued-not-started jobs receive no consensus completion. Their
        // retryable-failure cleanup runs below so network async markers are
        // released while the unprocessed blocks stay re-requestable.
        orphaned.swap(m_queue);
        for (const auto& pending : orphaned) {
            pending->job.cancelled->store(true, std::memory_order_relaxed);
            m_pending.erase(pending->job.GetHeader().GetHash());
        }
        threads.swap(m_threads);
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

bool MatMulVerifyWorker::HigherPriority(const Pending& lhs, const Pending& rhs)
{
    const auto lp{static_cast<uint8_t>(lhs.job.priority)};
    const auto rp{static_cast<uint8_t>(rhs.job.priority)};
    if (lp != rp) return lp > rp;
    return lhs.sequence < rhs.sequence;
}

void MatMulVerifyWorker::WorkerLoop()
{
    util::ThreadRename("mmverify");
    for (;;) {
        std::shared_ptr<Pending> pending;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this]() { return m_stopped || !m_queue.empty(); });
            if (m_stopped) return; // remaining queued jobs are drained by Stop()
            size_t best{0};
            for (size_t i = 1; i < m_queue.size(); ++i) {
                if (HigherPriority(*m_queue[i], *m_queue[best])) best = i;
            }
            pending = m_queue[best];
            m_queue.erase(m_queue.begin() + best);
            pending->running = true;
        }

        Job& job{pending->job};
        const CBlockHeader& header{job.GetHeader()};
        const uint256 hash{header.GetHash()};
        bool ok{false};
        bool local_execution_failure{false};
        if (job.cancelled->load(std::memory_order_relaxed)) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_pending.erase(hash);
            continue;
        }
        matmul::v4::rc::RCAcceleratorScheduler::Lease
            accelerator_lease;
        const bool trusted_exact_replay{
            !m_verify_override &&
            node::matmul_trusted::IsTrustedMirror() &&
            m_params.IsMatMulRCActive(job.height) &&
            !m_params.IsMatMulRCCoupledActive(job.height)};
        if (!m_verify_override &&
            m_params.IsMatMulRCFamilyActive(job.height) &&
            !trusted_exact_replay) {
            const auto device_priority{
                job.priority == Priority::AuthenticatedTipChild
                    ? matmul::v4::rc::RCAcceleratorScheduler::
                          Priority::TipValidation
                    : matmul::v4::rc::RCAcceleratorScheduler::
                          Priority::SpeculativeValidation};
            accelerator_lease =
                matmul::v4::rc::GetRCAcceleratorScheduler().Acquire(
                    device_priority, job.cancelled.get(),
                    strprintf("verify:%s:%d", hash.ToString(),
                              job.height));
            if (!accelerator_lease) {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_pending.erase(hash);
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
            job.cancelled.get()};
        if (m_verify_override) {
            if (job.block) {
                ok = m_verify_override(
                    *job.block, job.height, job.parent_median_time_past);
            } else {
                CBlock synthetic{header};
                ok = m_verify_override(
                    synthetic, job.height, job.parent_median_time_past);
            }
        } else if (trusted_exact_replay) {
            const auto wait_result{
                node::matmul_trusted::WaitForQuorum(
                    hash, job.height,
                    [&job] {
                        return job.cancelled->load(
                            std::memory_order_relaxed);
                    })};
            ok = wait_result ==
                matmul::trusted::WaitResult::Quorum;
            local_execution_failure = !ok;
            if (ok) {
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
                LogWarning(
                    "matmul trusted mirror deferred: block=%s height=%d "
                    "result=%s (retryable, peer not punished)\n",
                    hash.ToString(), job.height,
                    matmul::trusted::WaitResultName(wait_result));
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
            if (sf.IsLeader()) {
                ok = verify_pure();
                // Cancellation means no verdict. Publishing the cancellation
                // result would poison followers and the persistent header
                // memo, especially when a valid replay reports false solely
                // because the cancellation boundary fired.
                if (!job.cancelled->load(std::memory_order_relaxed) &&
                    !local_execution_failure) {
                    sf.SetResult(ok); // publish before ~sf releases waiters
                }
            } else if (const auto leader_result{sf.LeaderResult()}) {
                ok = *leader_result; // sketch already Put() on an accepted block
            } else {
                // Leader exited without publishing: decide ourselves.
                ok = verify_pure();
            }
            if (!job.cancelled->load(std::memory_order_relaxed) &&
                !local_execution_failure &&
                !(carrier_missing && !ok)) {
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
            const bool retryable_without_verdict{
                local_execution_failure ||
                job.cancelled->load(std::memory_order_relaxed)};
            if (retryable_without_verdict) {
                if (job.retryable_failure) {
                    retryable_failures.push_back(
                        std::move(job.retryable_failure));
                }
                std::move(
                    pending->follower_retryable_failures.begin(),
                    pending->follower_retryable_failures.end(),
                    std::back_inserter(retryable_failures));
            } else if (!job.cancelled->load(std::memory_order_relaxed)) {
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
