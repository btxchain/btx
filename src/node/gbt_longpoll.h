// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_NODE_GBT_LONGPOLL_H
#define BTX_NODE_GBT_LONGPOLL_H

#include <algorithm>
#include <atomic>
#include <chrono>

namespace node {

/** Absolute getblocktemplate long-poll lifetime (0.34.1 F5). */
inline constexpr std::chrono::seconds GBT_LONGPOLL_LIFETIME{60};

/** Match httpserver.h DEFAULT_HTTP_THREADS without a mining.cpp→httpserver edge. */
inline constexpr int GBT_LONGPOLL_DEFAULT_RPCTHREADS{16};

/** Cap concurrent GBT long-poll waiters so they cannot take the whole RPC pool (F6). */
[[nodiscard]] inline int GbtLongPollWaiterCap(int rpcthreads)
{
    return std::max(1, rpcthreads / 4);
}

[[nodiscard]] inline bool GbtLongPollLifetimeExpired(
    std::chrono::steady_clock::time_point start,
    std::chrono::steady_clock::time_point now,
    std::chrono::milliseconds lifetime = GBT_LONGPOLL_LIFETIME)
{
    return now >= start && (now - start) >= lifetime;
}

/** Process-wide counting slot. TryAcquire fails closed when the cap is full. */
class GbtLongPollWaiterSlot
{
    std::atomic<int>& m_waiters;
    const int m_cap;
    bool m_held{false};

public:
    GbtLongPollWaiterSlot(std::atomic<int>& waiters, int cap)
        : m_waiters(waiters), m_cap(std::max(1, cap)) {}
    GbtLongPollWaiterSlot(const GbtLongPollWaiterSlot&) = delete;
    GbtLongPollWaiterSlot& operator=(const GbtLongPollWaiterSlot&) = delete;
    ~GbtLongPollWaiterSlot()
    {
        if (m_held) {
            m_waiters.fetch_sub(1, std::memory_order_acq_rel);
        }
    }

    [[nodiscard]] bool TryAcquire()
    {
        int cur = m_waiters.load(std::memory_order_relaxed);
        while (cur < m_cap) {
            if (m_waiters.compare_exchange_weak(cur, cur + 1,
                                                std::memory_order_acq_rel,
                                                std::memory_order_relaxed)) {
                m_held = true;
                return true;
            }
        }
        return false;
    }
};

} // namespace node

#endif // BTX_NODE_GBT_LONGPOLL_H
