// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_synchold/book.h>

#include <modelnet/swarm_synchold/limits.h>

#include <utility>

namespace modelnet {

bool SwarmSyncHoldBook::contains(const std::string& name) const
{
    if (name.empty()) return false;
    return m_requests.find(name) != m_requests.end();
}

std::string SwarmSyncHoldBook::name_of(const std::string& name) const
{
    const auto found = m_requests.find(name);
    if (found == m_requests.end()) return {};
    return found->second.name();
}

std::size_t SwarmSyncHoldBook::size() const
{
    return m_requests.size();
}

bool SwarmSyncHoldBook::synced() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.synced()) return true;
    }
    return kSwarmSyncHoldSynced;
}

int64_t SwarmSyncHoldBook::bytes_moved() const
{
    int64_t total = kSwarmSyncHoldBytesMoved;
    for (const auto& entry : m_requests) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmSyncHoldBook::gpu() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmSyncHoldGpu;
}

bool SwarmSyncHoldBook::launched() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.launched()) return true;
    }
    return kSwarmSyncHoldLaunched;
}

bool SwarmSyncHoldBook::store(const std::string& name)
{
    if (contains(name)) return false;
    SwarmSyncHoldRecord record = SwarmSyncHoldRecord::Make(name);
    if (!SwarmSyncHoldRecordUsable(record)) return false;
    m_requests.emplace(name, std::move(record));
    return true;
}

} // namespace modelnet
