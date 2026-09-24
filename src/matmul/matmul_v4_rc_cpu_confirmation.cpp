// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_cpu_confirmation.h>

#include <arith_uint256.h>
#include <hash.h>
#include <logging.h>
#include <matmul/matmul_v4_rc.h>
#include <util/threadnames.h>

#include <algorithm>
#include <mutex>
#include <utility>

namespace matmul::v4::rc {

uint256 RCCpuConfirmationKey(const CBlockHeader& header,
                             const RCEpisodeParams& p, int32_t height,
                             const arith_uint256* target, uint32_t profile)
{
    return (HashWriter{} << header.GetHash() << height << p.rounds << p.d_head
            << p.n_q << p.n_ctx << p.L_lyr << p.d_model << p.d_ff << p.b_seq
            << p.T_leaf << (target != nullptr)
            << (target ? ArithToUint256(*target) : uint256{}) << profile
            << static_cast<uint8_t>(GetRCExactReplayExecutionPolicy())
            << static_cast<uint8_t>(GetRCExactReplayCpuConfirmation() ? 1 : 0)).GetHash();
}

RCCpuConfirmationQueue& GetRCCpuConfirmationQueue()
{
    // Process-lifetime object. Interrupt/Shutdown Stop() it; a later Get()
    // must not delete the published instance (UAF on retained ExactReplay
    // pointers) or reopen admission. Tests call ResetForTest() after Stop()
    // once every caller is quiescent.
    static RCCpuConfirmationQueue queue;
    return queue;
}

RCCpuConfirmationQueue::~RCCpuConfirmationQueue() { Stop(); }

std::optional<ExactReplayVerifyResult> RCCpuConfirmationQueue::Lookup(const uint256& key)
{
    std::lock_guard lock{m_mutex};
    const auto it{m_entries.find(key)};
    if (it == m_entries.end()) return std::nullopt;
    auto result{it->second.result};
    // A cancelled/failed/inconclusive CPU execution must be eligible for a
    // fresh attempt. Never memoize these as invalid consensus.
    if (it->second.complete &&
        result.outcome != ExactReplayVerifyOutcome::Valid &&
        result.outcome != ExactReplayVerifyOutcome::InvalidConsensus) {
        m_entries.erase(it);
        std::erase(m_completed, key);
    }
    return result;
}

ExactReplayVerifyResult RCCpuConfirmationQueue::Submit(
    const uint256& key, const uint256& block_hash,
    ExactReplayVerifyResult pending, Work work)
{
    std::lock_guard lock{m_mutex};
    if (const auto it{m_entries.find(key)}; it != m_entries.end()) return it->second.result;
    pending.ok = false;
    pending.outcome = ExactReplayVerifyOutcome::LocalAcceleratorFailure;
    pending.failure_kind = RCExactReplayFailureKind::UnconfirmedDigestMismatch;
    pending.acceleration_failure = m_stopping ? "cpu_confirmation_stopped"
        : m_pending >= MAX_PENDING ? "cpu_confirmation_capacity" : "cpu_confirmation_pending";
    pending.note = "ExactReplay: " + pending.acceleration_failure + "; block remains retryable; GPU validation remains available";
    pending.operator_recovery = "automatic retry; portable CPU confirmation is bounded and independent of GPU validation";
    if (m_stopping || m_pending >= MAX_PENDING) return pending;
    // Launch before publishing the first job, so thread creation failure
    // cannot strand an entry that no worker will ever service.
    if (!m_thread.joinable()) m_thread = std::thread{&RCCpuConfirmationQueue::Run, this};
    m_entries.emplace(key, Entry{block_hash, pending, false, std::move(work)});
    m_waiting.push_back(key);
    ++m_pending;
    m_cv.notify_one();
    return pending;
}

bool RCCpuConfirmationQueue::Pending(const uint256& block_hash) const
{
    std::lock_guard lock{m_mutex};
    return std::any_of(m_entries.begin(), m_entries.end(), [&](const auto& item) {
        return !item.second.complete && item.second.block_hash == block_hash;
    });
}

void RCCpuConfirmationQueue::Stop()
{
    std::lock_guard stop_lock{m_stop_mutex};
    {
        std::lock_guard lock{m_mutex};
        m_stopping.store(true, std::memory_order_release);
    }
    m_cv.notify_all();
    if (m_thread.joinable()) m_thread.join();
    std::lock_guard lock{m_mutex};
    m_entries.clear();
    m_waiting.clear();
    m_completed.clear();
    m_pending = 0;
}

bool RCCpuConfirmationQueue::Stopped() const
{
    return m_stopping.load(std::memory_order_acquire) && !m_thread.joinable();
}

void RCCpuConfirmationQueue::ResetForTest()
{
    Stop();
    std::lock_guard lock{m_mutex};
    m_stopping.store(false, std::memory_order_release);
}

void RCCpuConfirmationQueue::Run()
{
    util::ThreadRename("b-mmconfirm");
    const ScopedExactReplayCancellation cancellation{&m_stopping};
    for (;;) {
        std::unique_lock lock{m_mutex};
        m_cv.wait(lock, [&] { return m_stopping || !m_waiting.empty(); });
        if (m_stopping) return;
        const auto key{m_waiting.front()};
        m_waiting.pop_front();
        auto& entry{m_entries.at(key)};
        const auto block_hash{entry.block_hash};
        auto result{entry.result};
        auto work{std::move(entry.work)};
        lock.unlock();
        LogInfo("ExactReplay CPU confirmation started: block=%s (background CPU lane; no GPU acquisition)\n", block_hash.ToString());
        try {
            result = work();
        } catch (...) {
            result.acceleration_failure = "cpu_confirmation_execution_failed";
            result.note = "ExactReplay: CPU confirmation failed; block remains retryable";
        }
        lock.lock();
        if (m_stopping) return; // shutdown never publishes a partial verdict
        auto& completed{m_entries.at(key)};
        completed.result = std::move(result);
        completed.complete = true;
        --m_pending;
        m_completed.push_back(key);
        while (m_completed.size() > MAX_RESULTS) {
            m_entries.erase(m_completed.front());
            m_completed.pop_front();
        }
        LogInfo("ExactReplay CPU confirmation finished: block=%s outcome=%s; ordinary validation retry will consume result\n",
                block_hash.ToString(), ExactReplayVerifyOutcomeName(completed.result.outcome));
    }
}

} // namespace matmul::v4::rc
