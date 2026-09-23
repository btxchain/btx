// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_CPU_CONFIRMATION_H
#define BTX_MATMUL_MATMUL_V4_RC_CPU_CONFIRMATION_H

#include <matmul/matmul_v4_rc_gkr.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <thread>

namespace matmul::v4::rc {

/** One portable confirmation at a time, outside validation workers and GPU
 * leases. Only bounded header/context/result data may be captured by Work;
 * never retain a block body, admission ticket, backend, or node callback.
 * Pending/capacity/cancellation are local retryable states, never verdicts. */
class RCCpuConfirmationQueue
{
public:
    static constexpr size_t MAX_PENDING{4}; // includes the running job
    static constexpr size_t MAX_RESULTS{64};
    using Work = std::function<ExactReplayVerifyResult()>;

    ~RCCpuConfirmationQueue();
    std::optional<ExactReplayVerifyResult> Lookup(const uint256& key);
    ExactReplayVerifyResult Submit(const uint256& key, const uint256& block_hash,
                                  ExactReplayVerifyResult pending, Work work);
    bool Pending(const uint256& block_hash) const;
    void Stop();
    [[nodiscard]] bool Stopped() const;

private:
    struct Entry {
        uint256 block_hash;
        ExactReplayVerifyResult result;
        bool complete{false};
        Work work;
    };
    void Run();
    mutable std::mutex m_mutex;
    std::mutex m_stop_mutex;
    std::condition_variable m_cv;
    std::map<uint256, Entry> m_entries;
    std::deque<uint256> m_waiting;
    std::deque<uint256> m_completed;
    size_t m_pending{0};
    std::atomic_bool m_stopping{false};
    std::thread m_thread;
};

/** Bind every consensus input and the local confirmation policy. */
uint256 RCCpuConfirmationKey(const CBlockHeader& header,
                             const RCEpisodeParams& params, int32_t height,
                             const arith_uint256* target, uint32_t profile);
RCCpuConfirmationQueue& GetRCCpuConfirmationQueue();

} // namespace matmul::v4::rc
#endif
