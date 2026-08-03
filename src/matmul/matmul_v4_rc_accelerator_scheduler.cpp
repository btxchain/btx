// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_accelerator_scheduler.h>

#include <consensus/params.h>
#include <logging.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_accel_policy.h>
#include <matmul/matmul_v4_rc_production_canary.h>

#include <algorithm>
#include <cassert>
#include <cmath>
#include <limits>
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

static_assert(
    RCAcceleratorScheduler::MAX_WAITERS_PER_LANE[0] +
            RCAcceleratorScheduler::MAX_WAITERS_PER_LANE[1] +
            RCAcceleratorScheduler::MAX_WAITERS_PER_LANE[2] +
            RCAcceleratorScheduler::MAX_WAITERS_PER_LANE[3] ==
        RCAcceleratorScheduler::MAX_TOTAL_WAITERS,
    "per-lane RC waiter reservations must equal the global bound");

uint64_t SaturatingWorkspaceAdd(uint64_t a, uint64_t b)
{
    if (b > std::numeric_limits<uint64_t>::max() - a) {
        return std::numeric_limits<uint64_t>::max();
    }
    return a + b;
}

uint64_t SaturatingWorkspaceMul(uint64_t a, uint64_t b)
{
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) {
        return std::numeric_limits<uint64_t>::max();
    }
    return a * b;
}

} // namespace

uint64_t EstimateRCExactReplayWorkspaceBytes(
    const RCEpisodeParams& params)
{
    const uint64_t q{
        SaturatingWorkspaceMul(params.n_q, params.d_head)};
    const uint64_t context{
        SaturatingWorkspaceMul(params.n_ctx, params.d_head)};
    const uint64_t phase1{SaturatingWorkspaceAdd(
        SaturatingWorkspaceAdd(q, SaturatingWorkspaceMul(2, context)), q)};

    // Fused-FFN weights are NOT square. W_up is d_model x d_ff and W_down is
    // d_ff x d_model (see the ExpandMxDispatched calls in RunEpisode), so each
    // matrix is d_model*d_ff elements. This used d_model*d_model, understating
    // every weight matrix by d_ff/d_model -- a factor of 4 at the shipped 4x
    // transformer expansion.
    const uint64_t weight_matrix{
        SaturatingWorkspaceMul(params.d_model, params.d_ff)};
    const uint64_t weights{SaturatingWorkspaceMul(
        SaturatingWorkspaceMul(2, params.L_lyr), weight_matrix)};
    const uint64_t activation{
        SaturatingWorkspaceMul(params.b_seq, params.d_model)};
    const uint64_t activations{SaturatingWorkspaceMul(
        SaturatingWorkspaceMul(2, uint64_t{params.L_lyr} + 1),
        activation)};
    // The fused-FFN intermediate H is b_seq x d_ff and was omitted entirely.
    // It is live across the up and down GEMMs, so it must be counted.
    const uint64_t ffn_intermediate{
        SaturatingWorkspaceMul(params.b_seq, params.d_ff)};
    // At the shipped Profile-1 dimensions this moves the estimate from
    // 2.625 GiB to 4.375 GiB against roughly 4.95 GiB actually allocated per
    // device. The old figure was low enough to admit a provider that then
    // cannot hold the episode -- an OOM on a validating node at production
    // dimensions, which is why this is an admission gate and not a report.
    return std::max(
        phase1,
        SaturatingWorkspaceAdd(SaturatingWorkspaceAdd(weights, activations),
                               ffn_intermediate));
}

bool RCExactReplayWorkspaceFits(
    const RCEpisodeParams& params, uint64_t capacity_bytes)
{
    const uint64_t required{
        EstimateRCExactReplayWorkspaceBytes(params)};
    return capacity_bytes != 0 && required != 0 &&
        required <= capacity_bytes;
}

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
    std::string label, const std::atomic_bool* external_cancelled,
    std::chrono::milliseconds max_queue_wait,
    uint64_t workspace_request_bytes)
{
    const auto queued{std::chrono::steady_clock::now()};
    auto waiter{std::make_shared<Waiter>()};
    waiter->priority = priority;
    waiter->preempt_latch = preempt_latch;
    waiter->external_cancelled = external_cancelled;
    waiter->label = std::move(label);
    waiter->queued = queued;
    waiter->deadline = queued +
        std::max(max_queue_wait, std::chrono::milliseconds{0});
    waiter->workspace_request_bytes = workspace_request_bytes;

    std::unique_lock<std::mutex> lock(m_mutex);
    waiter->sequence = m_next_sequence++;
    ++m_stats.requests;
    auto& lane_stats{m_stats.lanes[LaneIndex(priority)]};
    ++lane_stats.requests;
    m_stats.workspace_requested_bytes = workspace_request_bytes;
    m_stats.workspace_request_high_water_bytes =
        std::max(m_stats.workspace_request_high_water_bytes,
                 workspace_request_bytes);

    const uint64_t lane_waiters{static_cast<uint64_t>(std::count_if(
        m_waiters.begin(), m_waiters.end(),
        [priority](const auto& queued_waiter) {
            return queued_waiter->priority == priority;
        }))};
    if (m_waiters.size() >= MAX_TOTAL_WAITERS ||
        lane_waiters >= MAX_WAITERS_PER_LANE[LaneIndex(priority)]) {
        ++m_stats.queue_rejections;
        ++lane_stats.queue_rejections;
        return {};
    }
    if (workspace_request_bytes != 0 &&
        m_workspace_capacity_bytes != 0 &&
        workspace_request_bytes > m_workspace_capacity_bytes) {
        ++m_stats.capacity_rejections;
        ++lane_stats.capacity_rejections;
        return {};
    }
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
            m_active_owner_thread = std::this_thread::get_id();
            m_active_label = waiter->label;
            m_active_started = started;
            m_stats.workspace_reserved_bytes =
                waiter->workspace_request_bytes;
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
        const auto now{std::chrono::steady_clock::now()};
        if (now >= waiter->deadline) {
            std::erase(m_waiters, waiter);
            ++m_stats.timed_out_waits;
            ++lane_stats.timed_out_waits;
            m_stats.queue_depth = m_waiters.size();
            lock.unlock();
            m_cv.notify_all();
            return {};
        }
        // Cancellation flags are intentionally owned by callers, so poll at a
        // short interval in addition to explicit NotifyCancellation().
        m_cv.wait_for(
            lock,
            std::min(
                std::chrono::milliseconds{25},
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    waiter->deadline - now)));
    }
}

bool RCAcceleratorScheduler::CurrentThreadOwnsLease() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_active &&
        m_active_owner_thread == std::this_thread::get_id();
}

bool RCAcceleratorScheduler::CurrentThreadLeaseCoversWorkspace(
    uint64_t required_bytes) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return required_bytes != 0 && m_active &&
        m_active_owner_thread == std::this_thread::get_id() &&
        m_stats.workspace_reserved_bytes >= required_bytes;
}

void RCAcceleratorScheduler::ConfigureWorkspaceCapacity(
    std::string provider, uint64_t capacity_bytes)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_workspace_provider = std::move(provider);
    m_workspace_capacity_bytes = capacity_bytes;
    m_stats.workspace_provider = m_workspace_provider;
    m_stats.workspace_capacity_bytes = m_workspace_capacity_bytes;
}

void RCAcceleratorScheduler::RecordWorkspaceUsage(
    uint64_t current_bytes, bool allocation_failed)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    ++m_stats.workspace_telemetry_samples;
    m_stats.workspace_current_bytes = current_bytes;
    m_stats.workspace_high_water_bytes =
        std::max(m_stats.workspace_high_water_bytes, current_bytes);
    if (allocation_failed) ++m_stats.workspace_allocation_failures;
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
        started != m_active_started ||
        m_active_owner_thread != std::this_thread::get_id()) {
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
    m_active_owner_thread = {};
    m_active_label.clear();
    m_stats.workspace_reserved_bytes = 0;
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
    out.workspace_provider = m_workspace_provider;
    out.workspace_capacity_bytes = m_workspace_capacity_bytes;
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
    // Lane values are independent latest-component samples, not one
    // block-correlated candidate-start-to-receiving-tip observation. Never
    // convert them into an operational-readiness verdict. A future bounded
    // record must bind every component to one exact header first.
    out.correlated_end_to_end_sample = false;
    out.operationally_ready = out.correlated_end_to_end_sample &&
        out.complete_sample_set &&
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
    } else if (!out.correlated_end_to_end_sample) {
        out.reason =
            "latest-component estimate and hardware gates pass, but no block-correlated end-to-end sample exists";
    } else {
        out.reason = "correlated lifecycle and hardware evidence gates pass";
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
    m_stats.workspace_provider = m_workspace_provider;
    m_stats.workspace_capacity_bytes = m_workspace_capacity_bytes;
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
