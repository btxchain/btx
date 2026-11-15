// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rescap/book.h>

#include <modelnet/swarm_rescap/limits.h>

#include <utility>

namespace modelnet {

bool SwarmResCapBook::contains(int64_t threads) const
{
    if (threads < kSwarmResCapMinThreads || threads > kSwarmResCapThreadCap) return false;
    return m_raises.find(threads) != m_raises.end();
}

int64_t SwarmResCapBook::stored_threads(int64_t threads) const
{
    const auto found = m_raises.find(threads);
    if (found == m_raises.end()) return kSwarmResCapUnset;
    return found->second.threads();
}

std::size_t SwarmResCapBook::size() const
{
    return m_raises.size();
}

bool SwarmResCapBook::raised() const
{
    for (const auto& entry : m_raises) {
        if (entry.second.raised()) return true;
    }
    return kSwarmResCapRaised;
}

int64_t SwarmResCapBook::bytes_moved() const
{
    int64_t total = kSwarmResCapBytesMoved;
    for (const auto& entry : m_raises) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmResCapBook::gpu() const
{
    for (const auto& entry : m_raises) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmResCapGpu;
}

bool SwarmResCapBook::launched() const
{
    for (const auto& entry : m_raises) {
        if (entry.second.launched()) return true;
    }
    return kSwarmResCapLaunched;
}

bool SwarmResCapBook::store(int64_t threads)
{
    if (contains(threads)) return false;
    SwarmResCapRecord record = SwarmResCapRecord::Make(threads);
    if (!SwarmResCapRecordUsable(record)) return false;
    m_raises.emplace(threads, std::move(record));
    return true;
}

} // namespace modelnet
