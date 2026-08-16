// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_accelerator_scheduler.h>

#include <consensus/params.h>
#include <logging.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_accel_policy.h>
#include <matmul/matmul_v4_rc_production_canary.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdlib>
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
    // Profile-1 seeded CUDA operand generation retains one maximum-size
    // mantissa/output pair, scales, SHA blocks, scan counters/offsets, and CUB
    // temporary storage. The estimate deliberately uses an upper bound for
    // scan storage so admission never depends on a toolkit-specific CUB size.
    const uint64_t largest_seeded_operand{std::max(
        SaturatingWorkspaceMul(params.n_ctx, params.d_head),
        weight_matrix)};
    const uint64_t seeded_blocks{SaturatingWorkspaceAdd(
        largest_seeded_operand / 40, 1024)};
    const uint64_t seeded_expand_scratch{SaturatingWorkspaceAdd(
        kRCSeededExpandScanTempBaseBytes,
        SaturatingWorkspaceAdd(
            SaturatingWorkspaceAdd(
                SaturatingWorkspaceMul(2, largest_seeded_operand),
                largest_seeded_operand / 32),
            SaturatingWorkspaceMul(
                40 + kRCSeededExpandScanTempBytesPerBlock,
                seeded_blocks)))};
    // Keep the persistent fused workspace and the persistent seeded expansion
    // scratch additive. Both allocations can be live at once, so taking only
    // their maximum would understate device-capacity admission.
    const uint64_t established_workspace{std::max(
        phase1,
        SaturatingWorkspaceAdd(SaturatingWorkspaceAdd(weights, activations),
                               ffn_intermediate))};
    if (UseDatacenterSharedFfnWeights(params)) {
        // Profile 2 does not dispatch the Profile-1 seeded CUDA lanes.
        return established_workspace;
    }
    return SaturatingWorkspaceAdd(
        established_workspace, seeded_expand_scratch);
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
    const auto now{std::chrono::steady_clock::now()};
    const auto anti_starve{CandidateMiningAntiStarveQuantum()};
    const auto mining_starved{
        [&](const std::shared_ptr<Waiter>& queued_waiter) {
            return queued_waiter->priority == Priority::CandidateMining &&
                   anti_starve.count() > 0 &&
                   now - queued_waiter->queued >= anti_starve;
        }};
    const bool any_starved_mining{std::any_of(
        m_waiters.begin(), m_waiters.end(), mining_starved)};
    // A starved local mine takes the next free turn ahead of a
    // TipValidation / Speculative flood. WinnerReseal still outranks.
    if (any_starved_mining && waiter->priority != Priority::WinnerReseal &&
        !mining_starved(waiter)) {
        return false;
    }
    for (const auto& candidate : m_waiters) {
        if (candidate == waiter) continue;
        if (mining_starved(waiter)) {
            if (candidate->priority == Priority::WinnerReseal) {
                return false;
            }
            if (candidate->priority == Priority::CandidateMining &&
                candidate->sequence < waiter->sequence) {
                return false;
            }
            continue;
        }
        if (static_cast<uint8_t>(candidate->priority) >
                static_cast<uint8_t>(waiter->priority) ||
            (candidate->priority == waiter->priority &&
             candidate->sequence < waiter->sequence)) {
            return false;
        }
    }
    return true;
}

std::chrono::milliseconds
RCAcceleratorScheduler::CandidateMiningMinLeaseQuantum()
{
    const char* env = std::getenv("BTX_RC_CANDIDATE_MINING_LEASE_MS");
    if (env != nullptr && env[0] != '\0') {
        int64_t parsed{0};
        if (ParseInt64(env, &parsed) && parsed >= 0) {
            return std::chrono::milliseconds{parsed};
        }
    }
    return DEFAULT_CANDIDATE_MINING_MIN_LEASE;
}

std::chrono::milliseconds
RCAcceleratorScheduler::CandidateMiningAntiStarveQuantum()
{
    const char* env = std::getenv("BTX_RC_CANDIDATE_MINING_ANTI_STARVE_MS");
    if (env != nullptr && env[0] != '\0') {
        int64_t parsed{0};
        if (ParseInt64(env, &parsed) && parsed >= 0) {
            return std::chrono::milliseconds{parsed};
        }
    }
    return DEFAULT_CANDIDATE_MINING_ANTI_STARVE;
}

bool RCAcceleratorScheduler::HasHigherPriorityWaiter(Priority owner) const
{
    for (const auto& waiter : m_waiters) {
        if (static_cast<uint8_t>(waiter->priority) >
            static_cast<uint8_t>(owner)) {
            return true;
        }
    }
    return false;
}

bool RCAcceleratorScheduler::MaybePreemptActiveOwner(Priority requester)
{
    if (!m_active || m_active_preempt_latch == nullptr ||
        static_cast<uint8_t>(requester) <=
            static_cast<uint8_t>(m_active_priority)) {
        return false;
    }

    // Give CandidateMining a minimum lease quantum so tip validation bursts
    // cannot abort every nonce attempt after a few milliseconds. Validation
    // still outranks mining after the quantum; combined authority+miner
    // remains degraded versus a dedicated miner.
    if (m_active_priority == Priority::CandidateMining) {
        const auto quantum{CandidateMiningMinLeaseQuantum()};
        const auto held{
            std::chrono::steady_clock::now() - m_active_started};
        if (quantum.count() > 0 && held < quantum) {
            ++m_stats.preemption_deferred;
            m_combined_authority_miner_degraded = true;
            m_stats.combined_authority_miner_degraded = true;
            return false;
        }
    }

    if (!m_active_preempt_latch->exchange(
            true, std::memory_order_relaxed)) {
        ++m_stats.preemption_requests;
        if (m_active_priority == Priority::CandidateMining) {
            m_combined_authority_miner_degraded = true;
            m_stats.combined_authority_miner_degraded = true;
        }
        return true;
    }
    return false;
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
    m_stats.candidate_mining_min_lease_ms =
        CandidateMiningMinLeaseQuantum().count();

    // Self-recovery: drop waiters whose deadline already passed so a
    // saturation burst cannot pin the queue until process restart.
    const auto now_reap{std::chrono::steady_clock::now()};
    const auto reaped{std::erase_if(
        m_waiters, [&](const std::shared_ptr<Waiter>& queued_waiter) {
            if (now_reap < queued_waiter->deadline) return false;
            ++m_stats.timed_out_waits;
            ++m_stats.lanes[LaneIndex(queued_waiter->priority)]
                  .timed_out_waits;
            return true;
        })};
    if (reaped > 0) {
        m_stats.queue_depth = m_waiters.size();
        m_cv.notify_all();
    }

    auto lane_waiters{static_cast<uint64_t>(std::count_if(
        m_waiters.begin(), m_waiters.end(),
        [priority](const auto& queued_waiter) {
            return queued_waiter->priority == priority;
        }))};
    if (m_waiters.size() >= MAX_TOTAL_WAITERS ||
        lane_waiters >= MAX_WAITERS_PER_LANE[LaneIndex(priority)]) {
        // Displace the oldest same-or-lower-priority waiter so a real
        // TipValidation child can enter after a sibling flood filled the
        // lane. Equal-priority FIFO: the new request is newer, so the
        // oldest occupant is the flood leftover.
        auto victim{m_waiters.end()};
        for (auto it{m_waiters.begin()}; it != m_waiters.end(); ++it) {
            // WinnerReseal waiters are never stolen.
            if ((*it)->priority == Priority::WinnerReseal) {
                continue;
            }
            // CandidateMining waiters are a reserved lane. A TipValidation
            // sibling flood must not steal them (live miner: own ExactReplay
            // starved at 69–198 same-height siblings, ~9–18% win rate).
            if ((*it)->priority == Priority::CandidateMining) {
                continue;
            }
            // Local CandidateMining may displace a TipValidation flood
            // leftover so submitblock can enter during a sibling storm.
            if (static_cast<uint8_t>((*it)->priority) >
                    static_cast<uint8_t>(priority) &&
                !(priority == Priority::CandidateMining &&
                  (*it)->priority == Priority::TipValidation)) {
                continue;
            }
            if (victim == m_waiters.end() ||
                (*it)->sequence < (*victim)->sequence) {
                victim = it;
            }
        }
        if (victim != m_waiters.end()) {
            const bool strictly_lower{
                static_cast<uint8_t>((*victim)->priority) <
                static_cast<uint8_t>(priority)};
            const bool displace_tip_validation_flood{
                (*victim)->priority == priority &&
                priority == Priority::TipValidation};
            const bool mining_steals_tip_flood{
                priority == Priority::CandidateMining &&
                (*victim)->priority == Priority::TipValidation};
            if (strictly_lower || displace_tip_validation_flood ||
                mining_steals_tip_flood) {
                ++m_stats.cancelled_waits;
                ++m_stats.lanes[LaneIndex((*victim)->priority)]
                      .cancelled_waits;
                m_waiters.erase(victim);
                m_stats.queue_depth = m_waiters.size();
                m_cv.notify_all();
                lane_waiters = static_cast<uint64_t>(std::count_if(
                    m_waiters.begin(), m_waiters.end(),
                    [priority](const auto& queued_waiter) {
                        return queued_waiter->priority == priority;
                    }));
            }
        }
    }
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

    bool log_combined_degraded{false};
    if (MaybePreemptActiveOwner(priority)) {
        // Preempt latch set.
    } else if (
        m_active &&
        m_active_priority == Priority::CandidateMining &&
        static_cast<uint8_t>(priority) >
            static_cast<uint8_t>(m_active_priority) &&
        m_combined_authority_miner_degraded &&
        !m_logged_combined_degraded) {
        m_logged_combined_degraded = true;
        log_combined_degraded = true;
    }

    for (;;) {
        if (log_combined_degraded) {
            lock.unlock();
            LogPrintf(
                "MATMUL RC SCHEDULER: combined authority+miner degraded — "
                "CandidateMining holds a %lld ms min-lease quantum before "
                "yielding to %s (set BTX_RC_CANDIDATE_MINING_LEASE_MS to "
                "tune; 0 disables). Prefer separating miner and tip "
                "authority for full mining throughput.\n",
                static_cast<long long>(
                    CandidateMiningMinLeaseQuantum().count()),
                ToString(priority));
            lock.lock();
            log_combined_degraded = false;
        }
        // Re-check deferred CandidateMining preemption once the quantum elapses.
        if (m_active &&
            m_active_priority == Priority::CandidateMining &&
            HasHigherPriorityWaiter(Priority::CandidateMining)) {
            const auto quantum{CandidateMiningMinLeaseQuantum()};
            const auto held{
                std::chrono::steady_clock::now() - m_active_started};
            if (quantum.count() == 0 || held >= quantum) {
                if (m_active_preempt_latch != nullptr &&
                    !m_active_preempt_latch->exchange(
                        true, std::memory_order_relaxed)) {
                    ++m_stats.preemption_requests;
                    m_combined_authority_miner_degraded = true;
                    m_stats.combined_authority_miner_degraded = true;
                }
            }
        }
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
        if (std::find(m_waiters.begin(), m_waiters.end(), waiter) ==
            m_waiters.end()) {
            // Displaced by a later higher-or-equal priority Acquire so the
            // sibling flood cannot pin both TipValidation slots.
            lock.unlock();
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
        // When CandidateMining holds a deferred quantum, wake promptly once
        // the remaining quantum elapses so tip validation is not stuck on the
        // generic 25 ms poll alone.
        auto wait_slice{std::chrono::milliseconds{25}};
        if (m_active &&
            m_active_priority == Priority::CandidateMining &&
            HasHigherPriorityWaiter(Priority::CandidateMining)) {
            const auto quantum{CandidateMiningMinLeaseQuantum()};
            if (quantum.count() > 0) {
                const auto held{now - m_active_started};
                if (held < quantum) {
                    wait_slice = std::min(
                        wait_slice,
                        std::chrono::duration_cast<
                            std::chrono::milliseconds>(
                            quantum - held));
                    if (wait_slice.count() <= 0) {
                        wait_slice = std::chrono::milliseconds{1};
                    }
                }
            }
        }
        if (priority == Priority::CandidateMining) {
            const auto anti_starve{CandidateMiningAntiStarveQuantum()};
            if (anti_starve.count() > 0) {
                const auto waited{now - waiter->queued};
                if (waited < anti_starve) {
                    wait_slice = std::min(
                        wait_slice,
                        std::chrono::duration_cast<
                            std::chrono::milliseconds>(
                            anti_starve - waited));
                    if (wait_slice.count() <= 0) {
                        wait_slice = std::chrono::milliseconds{1};
                    }
                }
            }
        }
        // Cancellation flags are intentionally owned by callers, so poll at a
        // short interval in addition to explicit NotifyCancellation().
        m_cv.wait_for(
            lock,
            std::min(
                wait_slice,
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
    out.combined_authority_miner_degraded =
        m_combined_authority_miner_degraded;
    out.candidate_mining_min_lease_ms =
        CandidateMiningMinLeaseQuantum().count();
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
    m_stats.candidate_mining_min_lease_ms =
        CandidateMiningMinLeaseQuantum().count();
    m_combined_authority_miner_degraded = false;
    m_logged_combined_degraded = false;
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
