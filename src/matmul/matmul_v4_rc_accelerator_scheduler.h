// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_ACCELERATOR_SCHEDULER_H
#define BTX_MATMUL_MATMUL_V4_RC_ACCELERATOR_SCHEDULER_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace matmul::v4::rc {

/**
 * Process-wide owner for the scarce RC ExactReplay accelerator submitter.
 *
 * Device backends may serialize internally, but a backend mutex cannot express
 * whether the waiter is authenticating the active-tip child, resealing a local
 * winner, mining another candidate, or checking speculative work. This
 * scheduler provides that policy boundary. Callers retain their own
 * consensus-neutral cancellation handling; preemption only raises the supplied
 * cancellation flag.
 */
class RCAcceleratorScheduler
{
public:
    enum class Priority : uint8_t {
        SpeculativeValidation = 0,
        CandidateMining = 1,
        WinnerReseal = 2,
        TipValidation = 3,
    };

    struct Stats {
        uint64_t requests{0};
        uint64_t acquisitions{0};
        uint64_t completions{0};
        uint64_t cancelled_waits{0};
        uint64_t preemption_requests{0};
        uint64_t queue_depth{0};
        uint64_t queue_high_water{0};
        bool active{false};
        Priority active_priority{Priority::SpeculativeValidation};
        std::string active_label;
        double active_wall_s{0};
        double last_queue_wait_s{0};
        double max_queue_wait_s{0};
        double last_execution_s{0};
        double max_execution_s{0};
    };

    class Lease
    {
    public:
        Lease() = default;
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& other) noexcept;
        Lease& operator=(Lease&& other) noexcept;
        ~Lease();

        explicit operator bool() const { return m_owner != nullptr; }
        double QueueWaitSeconds() const { return m_queue_wait_s; }
        Priority GetPriority() const { return m_priority; }

    private:
        friend class RCAcceleratorScheduler;
        Lease(RCAcceleratorScheduler* owner, Priority priority,
              double queue_wait_s,
              std::chrono::steady_clock::time_point started);
        void Release();

        RCAcceleratorScheduler* m_owner{nullptr};
        Priority m_priority{Priority::SpeculativeValidation};
        double m_queue_wait_s{0};
        std::chrono::steady_clock::time_point m_started{};
    };

    /**
     * Wait for exclusive accelerator ownership. A higher-priority request asks
     * the current lower-priority owner to cancel by setting `preempt_latch`.
     * `external_cancelled` observes a separate owner (for example the miner's
     * tip/template abort flag) without allowing the scheduler to mutate it.
     * Returns an empty lease when either latch fires before admission.
     */
    Lease Acquire(
        Priority priority, std::atomic_bool* preempt_latch,
        std::string label,
        const std::atomic_bool* external_cancelled = nullptr);

    /** Wake cancelled waiters promptly during shutdown/tip change. */
    void NotifyCancellation();

    [[nodiscard]] Stats GetStats() const;

    /** Test-only; succeeds only while there is no owner or waiter. */
    bool ResetStatsForTest();

private:
    struct Waiter {
        Priority priority{Priority::SpeculativeValidation};
        uint64_t sequence{0};
        std::atomic_bool* preempt_latch{nullptr};
        const std::atomic_bool* external_cancelled{nullptr};
        std::string label;
        std::chrono::steady_clock::time_point queued{};
    };

    void Release(Priority priority,
                 std::chrono::steady_clock::time_point started);
    [[nodiscard]] bool IsFirst(const std::shared_ptr<Waiter>& waiter) const;

    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::vector<std::shared_ptr<Waiter>> m_waiters;
    uint64_t m_next_sequence{0};
    bool m_active{false};
    Priority m_active_priority{Priority::SpeculativeValidation};
    std::atomic_bool* m_active_preempt_latch{nullptr};
    std::string m_active_label;
    std::chrono::steady_clock::time_point m_active_started{};
    Stats m_stats;
};

/** One scheduler is shared by validation, winner reseal, and candidate mining. */
RCAcceleratorScheduler& GetRCAcceleratorScheduler();

const char* ToString(RCAcceleratorScheduler::Priority priority);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_ACCELERATOR_SCHEDULER_H
