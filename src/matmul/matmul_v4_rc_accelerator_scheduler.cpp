// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_accelerator_scheduler.h>

#include <algorithm>
#include <utility>

namespace matmul::v4::rc {

namespace {

double Seconds(std::chrono::steady_clock::duration duration)
{
    return std::chrono::duration<double>(duration).count();
}

} // namespace

RCAcceleratorScheduler::Lease::Lease(
    RCAcceleratorScheduler* owner, Priority priority,
    double queue_wait_s, std::chrono::steady_clock::time_point started)
    : m_owner{owner},
      m_priority{priority},
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
    m_owner->Release(m_priority, m_started);
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
    Priority priority, std::atomic_bool* cancelled, std::string label)
{
    const auto queued{std::chrono::steady_clock::now()};
    auto waiter{std::make_shared<Waiter>()};
    waiter->priority = priority;
    waiter->cancelled = cancelled;
    waiter->label = std::move(label);
    waiter->queued = queued;

    std::unique_lock<std::mutex> lock(m_mutex);
    waiter->sequence = m_next_sequence++;
    ++m_stats.requests;
    m_waiters.push_back(waiter);
    m_stats.queue_depth = m_waiters.size();
    m_stats.queue_high_water =
        std::max<uint64_t>(m_stats.queue_high_water, m_waiters.size());

    if (m_active &&
        static_cast<uint8_t>(priority) >
            static_cast<uint8_t>(m_active_priority) &&
        m_active_cancelled != nullptr &&
        !m_active_cancelled->exchange(true, std::memory_order_relaxed)) {
        ++m_stats.preemption_requests;
    }

    for (;;) {
        if (cancelled != nullptr &&
            cancelled->load(std::memory_order_relaxed)) {
            std::erase(m_waiters, waiter);
            ++m_stats.cancelled_waits;
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
            m_active_cancelled = cancelled;
            m_active_label = waiter->label;
            m_active_started = started;
            ++m_stats.acquisitions;
            m_stats.queue_depth = m_waiters.size();
            m_stats.active = true;
            m_stats.active_priority = priority;
            m_stats.active_label = m_active_label;
            m_stats.last_queue_wait_s = wait_s;
            m_stats.max_queue_wait_s =
                std::max(m_stats.max_queue_wait_s, wait_s);
            return Lease{this, priority, wait_s, started};
        }
        // Cancellation flags are intentionally owned by callers, so poll at a
        // short interval in addition to explicit NotifyCancellation().
        m_cv.wait_for(lock, std::chrono::milliseconds{25});
    }
}

void RCAcceleratorScheduler::Release(
    Priority priority, std::chrono::steady_clock::time_point started)
{
    const auto finished{std::chrono::steady_clock::now()};
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_active || priority != m_active_priority) return;
    const double execution_s{Seconds(finished - started)};
    ++m_stats.completions;
    m_stats.last_execution_s = execution_s;
    m_stats.max_execution_s =
        std::max(m_stats.max_execution_s, execution_s);
    m_active = false;
    m_active_cancelled = nullptr;
    m_active_label.clear();
    m_stats.active = false;
    m_stats.active_label.clear();
    m_stats.active_wall_s = 0;
    m_cv.notify_all();
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

bool RCAcceleratorScheduler::ResetStatsForTest()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_active || !m_waiters.empty()) return false;
    m_stats = {};
    m_next_sequence = 0;
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
