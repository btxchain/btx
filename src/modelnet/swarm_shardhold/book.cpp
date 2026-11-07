// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_shardhold/book.h>

#include <modelnet/swarm_shardhold/limits.h>

#include <utility>

namespace modelnet {

bool SwarmShardHoldBook::contains(const std::string& name) const
{
    if (name.empty()) return false;
    return m_requests.find(name) != m_requests.end();
}

std::string SwarmShardHoldBook::name_of(const std::string& name) const
{
    const auto found = m_requests.find(name);
    if (found == m_requests.end()) return {};
    return found->second.name();
}

std::size_t SwarmShardHoldBook::size() const
{
    return m_requests.size();
}

bool SwarmShardHoldBook::sharded() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.sharded()) return true;
    }
    return kSwarmShardHoldSharded;
}

bool SwarmShardHoldBook::running() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.running()) return true;
    }
    return kSwarmShardHoldRunning;
}

int64_t SwarmShardHoldBook::bytes_moved() const
{
    int64_t total = kSwarmShardHoldBytesMoved;
    for (const auto& entry : m_requests) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmShardHoldBook::gpu() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmShardHoldGpu;
}

bool SwarmShardHoldBook::launched() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.launched()) return true;
    }
    return kSwarmShardHoldLaunched;
}

bool SwarmShardHoldBook::store(const std::string& name)
{
    if (contains(name)) return false;
    SwarmShardHoldRecord record = SwarmShardHoldRecord::Make(name);
    if (!SwarmShardHoldRecordUsable(record)) return false;
    m_requests.emplace(name, std::move(record));
    return true;
}

} // namespace modelnet
