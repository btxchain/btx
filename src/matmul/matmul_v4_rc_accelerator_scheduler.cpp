// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_accelerator_scheduler.h>

#include <consensus/params.h>
#include <logging.h>
#include <matmul/matmul_v4_rc_accel_policy.h>
#include <matmul/matmul_v4_rc_production_canary.h>

#include <algorithm>
#include <cassert>
#include <cmath>
#include <utility>

namespace matmul::v4::rc {

namespace {

double Seconds(std::chrono::steady_clock::duration duration)
{
    return std::chrono::duration<double>(duration).count();
}

size_t LaneIndex(RCAcceleratorScheduler::Priority priority)
{
    return static_cast<size_t>(priority);
}

} // namespace

RCAcceleratorScheduler::Lease::Lease(
    RCAcceleratorScheduler* owner, Priority priority,
    uint64_t token, double queue_wait_s,
    std::chrono::steady_clock::time_point started)
    : m_owner{owner},
      m_priority{priority},
      m_token{token},
      m_queue_wait_s{queue_wait_s},
      m_started{started}
{
}

RCAcceleratorScheduler::Lease::Lease(Lease&& other) noexcept
{
    *this = std::move(other);
}

RCAcceleratorScheduler::Lease&
RCAcceleratorScheduler::Lease::operator=(Lease&& other) noexcept
{
    if (this == &other) return *this;
    Release();
    m_owner = std::exchange(other.m_owner, nullptr);
    m_priority = other.m_priority;
    m_token = other.m_token;
    m_queue_wait_s = other.m_queue_wait_s;
    m_started = other.m_started;
    return *this;
}

RCAcceleratorScheduler::Lease::~Lease()
{
    Release();
}

void RCAcceleratorScheduler::Lease::Release()
{
    if (m_owner == nullptr) return;
    m_owner->Release(m_priority, m_token, m_started);
    m_owner = nullptr;
}

bool RCAcceleratorScheduler::IsFirst(
    const std::shared_ptr<Waiter>& waiter) const
{
    for (const auto& candidate : m_waiters) {
        if (candidate == waiter) continue;
        if (static_cast<uint8_t>(candidate->priority) >
                static_cast<uint8_t>(waiter->priority) ||
            (candidate->priority == waiter->priority &&
             candidate->sequence < waiter->sequence)) {
            return false;
        }
    }
    return true;
}

RCAcceleratorScheduler::Lease
RCAcceleratorScheduler::Acquire(
    Priority priority, std::atomic_bool* preempt_latch,
    std::string label, const std::atomic_bool* external_cancelled)
{
    const auto queued{std::chrono::steady_clock::now()};
    auto waiter{std::make_shared<Waiter>()};
    waiter->priority = priority;
    waiter->preempt_latch = preempt_latch;
    waiter->external_cancelled = external_cancelled;
    waiter->label = std::move(label);
    waiter->queued = queued;

    std::unique_lock<std::mutex> lock(m_mutex);
    waiter->sequence = m_next_sequence++;
    ++m_stats.requests;
    ++m_stats.lanes[LaneIndex(priority)].requests;
    m_waiters.push_back(waiter);
    m_stats.queue_depth = m_waiters.size();
    m_stats.queue_high_water =
        std::max<uint64_t>(m_stats.queue_high_water, m_waiters.size());

    if (m_active &&
        static_cast<uint8_t>(priority) >
            static_cast<uint8_t>(m_active_priority) &&
        m_active_preempt_latch != nullptr &&
        !m_active_preempt_latch->exchange(
            true, std::memory_order_relaxed)) {
        ++m_stats.preemption_requests;
    }

    for (;;) {
        if ((preempt_latch != nullptr &&
             preempt_latch->load(std::memory_order_relaxed)) ||
            (external_cancelled != nullptr &&
             external_cancelled->load(std::memory_order_relaxed))) {
            std::erase(m_waiters, waiter);
            ++m_stats.cancelled_waits;
            ++m_stats.lanes[LaneIndex(priority)].cancelled_waits;
            m_stats.queue_depth = m_waiters.size();
            lock.unlock();
            m_cv.notify_all();
            return {};
        }
        if (!m_active && IsFirst(waiter)) {
            std::erase(m_waiters, waiter);
            const auto started{std::chrono::steady_clock::now()};
            const double wait_s{Seconds(started - queued)};
            m_active = true;
            m_active_priority = priority;
            m_active_token = m_next_lease_token++;
            if (m_active_token == 0) {
                m_active_token = m_next_lease_token++;
            }
            m_active_preempt_latch = preempt_latch;
            m_active_label = waiter->label;
            m_active_started = started;
            ++m_stats.acquisitions;
            auto& lane{m_stats.lanes[LaneIndex(priority)]};
            ++lane.acquisitions;
            lane.last_queue_wait_s = wait_s;
            lane.max_queue_wait_s =
                std::max(lane.max_queue_wait_s, wait_s);
            m_stats.queue_depth = m_waiters.size();
            m_stats.active = true;
            m_stats.active_priority = priority;
            m_stats.active_label = m_active_label;
            m_stats.last_queue_wait_s = wait_s;
            m_stats.max_queue_wait_s =
                std::max(m_stats.max_queue_wait_s, wait_s);
            return Lease{
                this, priority, m_active_token, wait_s, started};
        }
        // Cancellation flags are intentionally owned by callers, so poll at a
        // short interval in addition to explicit NotifyCancellation().
        m_cv.wait_for(lock, std::chrono::milliseconds{25});
    }
}

bool RCAcceleratorScheduler::Release(
    Priority priority, uint64_t token,
    std::chrono::steady_clock::time_point started,
    bool assert_on_mismatch)
{
    const auto finished{std::chrono::steady_clock::now()};
    std::unique_lock<std::mutex> lock(m_mutex);
    if (!m_active || priority != m_active_priority ||
        token == 0 || token != m_active_token ||
        started != m_active_started) {
        ++m_stats.release_invariant_violations;
        const bool active{m_active};
        const Priority active_priority{m_active_priority};
        const uint64_t active_token{m_active_token};
        // Never enter the logging subsystem while owning the scheduler mutex:
        // shutdown/error logging can take unrelated locks and an invariant
        // path must not turn a diagnosable bad release into a process wedge.
        lock.unlock();
        LogPrintf(
            "MATMUL RC SCHEDULER INVARIANT: invalid lease release "
            "(active=%d active_priority=%s release_priority=%s "
            "active_token=%llu release_token=%llu)\n",
            active, ToString(active_priority), ToString(priority),
            static_cast<unsigned long long>(active_token),
            static_cast<unsigned long long>(token));
        if (assert_on_mismatch) {
            assert(false &&
                   "RC accelerator scheduler lease identity mismatch");
        }
        return false;
    }
    const double execution_s{Seconds(finished - started)};
    ++m_stats.completions;
    auto& lane{m_stats.lanes[LaneIndex(priority)]};
    ++lane.completions;
    lane.last_execution_s = execution_s;
    lane.max_execution_s =
        std::max(lane.max_execution_s, execution_s);
    m_stats.last_execution_s = execution_s;
    m_stats.max_execution_s =
        std::max(m_stats.max_execution_s, execution_s);
    m_active = false;
    m_active_token = 0;
    m_active_preempt_latch = nullptr;
    m_active_label.clear();
    m_stats.active = false;
    m_stats.active_label.clear();
    m_stats.active_wall_s = 0;
    lock.unlock();
    m_cv.notify_all();
    return true;
}

void RCAcceleratorScheduler::NotifyCancellation()
{
    m_cv.notify_all();
}

RCAcceleratorScheduler::Stats
RCAcceleratorScheduler::GetStats() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    Stats out{m_stats};
    out.queue_depth = m_waiters.size();
    out.active = m_active;
    out.active_priority = m_active_priority;
    out.active_label = m_active_label;
    if (m_active) {
        out.active_wall_s =
            Seconds(std::chrono::steady_clock::now() - m_active_started);
    }
    return out;
}

RCAcceleratorScheduler::LifecycleAssessment
RCAcceleratorScheduler::AssessLifecycle(double target_spacing_s) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    LifecycleAssessment out;
    out.target_spacing_s = target_spacing_s;
    const auto& candidate{
        m_stats.lanes[LaneIndex(Priority::CandidateMining)]};
    const auto& reseal{
        m_stats.lanes[LaneIndex(Priority::WinnerReseal)]};
    const auto& tip{
        m_stats.lanes[LaneIndex(Priority::TipValidation)]};
    out.candidate_measured = candidate.completions != 0;
    out.winner_reseal_measured = reseal.completions != 0;
    out.authenticated_relay_measured =
        m_stats.authenticated_relay_samples != 0;
    out.tip_validation_measured = tip.completions != 0;
    out.candidate_s = candidate.last_execution_s;
    out.winner_reseal_s = reseal.last_execution_s;
    out.authenticated_relay_s =
        m_stats.last_authenticated_relay_s;
    out.tip_validation_s = tip.last_execution_s;
    out.queue_wait_s = candidate.last_queue_wait_s +
        reseal.last_queue_wait_s + tip.last_queue_wait_s;
    out.complete_lifecycle_s = out.candidate_s +
        out.winner_reseal_s + out.authenticated_relay_s +
        out.tip_validation_s + out.queue_wait_s;
    out.complete_sample_set = out.candidate_measured &&
        out.winner_reseal_measured &&
        out.authenticated_relay_measured &&
        out.tip_validation_measured;
    out.within_target_spacing = out.complete_sample_set &&
        std::isfinite(target_spacing_s) && target_spacing_s > 0 &&
        out.complete_lifecycle_s < target_spacing_s;
    const auto production_canary{GetLastRCProductionCanaryStatus()};
    out.hardware_evidence_gates_passed =
        production_canary.manifest_has_reviewed_goldens &&
        production_canary.activation_ready &&
        Consensus::BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED;
    out.operationally_ready = out.complete_sample_set &&
        out.within_target_spacing &&
        out.hardware_evidence_gates_passed;
    if (!out.complete_sample_set) {
        out.reason =
            "missing candidate/reseal/relay/tip-validation lifecycle samples";
    } else if (!out.within_target_spacing) {
        out.reason =
            "complete lifecycle is not below target spacing";
    } else if (!out.hardware_evidence_gates_passed) {
        out.reason =
            "latest-component estimate is below target spacing but production goldens/startup canary remain unratified";
    } else {
        out.reason =
            "latest-component estimate and hardware gates pass; sustained correlated tail-latency evidence still required";
    }
    return out;
}

void RCAcceleratorScheduler::RecordAuthenticatedRelaySample(double relay_s)
{
    if (!std::isfinite(relay_s) || relay_s < 0) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    ++m_stats.authenticated_relay_samples;
    m_stats.last_authenticated_relay_s = relay_s;
    m_stats.max_authenticated_relay_s =
        std::max(m_stats.max_authenticated_relay_s, relay_s);
}

RCAcceleratorScheduler::AuthenticatedRelayObservation
RCAcceleratorScheduler::BeginAuthenticatedRelayObservation() const
{
    return {.announced = std::chrono::steady_clock::now()};
}

void RCAcceleratorScheduler::MarkAuthenticatedRelayBodyReceived(
    AuthenticatedRelayObservation& observation) const
{
    // The first complete body wins. Duplicate BLOCK/BLOCKTXN deliveries must
    // not change the measured network interval while validation is queued.
    if (!observation.body_received) {
        observation.body_received = std::chrono::steady_clock::now();
    }
}

bool RCAcceleratorScheduler::CommitAuthenticatedRelayObservation(
    AuthenticatedRelayObservation& observation)
{
    if (!observation.body_received ||
        observation.announced.time_since_epoch().count() == 0 ||
        *observation.body_received < observation.announced) {
        return false;
    }
    const double relay_s{
        Seconds(*observation.body_received - observation.announced)};
    observation.announced = {};
    observation.body_received.reset();
    RecordAuthenticatedRelaySample(relay_s);
    return true;
}

bool RCAcceleratorScheduler::TryMismatchedReleaseForTest(
    Priority priority, uint64_t token)
{
    std::chrono::steady_clock::time_point started;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_active) return false;
        started = m_active_started;
    }
    return Release(
        priority, token, started, /*assert_on_mismatch=*/false);
}

bool RCAcceleratorScheduler::ResetStatsForTest()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_active || !m_waiters.empty()) return false;
    m_stats = {};
    m_next_sequence = 0;
    m_next_lease_token = 1;
    return true;
}

RCAcceleratorScheduler& GetRCAcceleratorScheduler()
{
    static RCAcceleratorScheduler scheduler;
    return scheduler;
}

const char* ToString(RCAcceleratorScheduler::Priority priority)
{
    switch (priority) {
    case RCAcceleratorScheduler::Priority::SpeculativeValidation:
        return "speculative_validation";
    case RCAcceleratorScheduler::Priority::CandidateMining:
        return "candidate_mining";
    case RCAcceleratorScheduler::Priority::WinnerReseal:
        return "winner_reseal";
    case RCAcceleratorScheduler::Priority::TipValidation:
        return "tip_validation";
    }
    return "unknown";
}

} // namespace matmul::v4::rc
