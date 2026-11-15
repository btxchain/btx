// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_minehold/book.h>

#include <modelnet/swarm_minehold/limits.h>

#include <utility>

namespace modelnet {

bool SwarmMineHoldBook::contains(const std::string& name) const
{
    if (name.empty()) return false;
    return m_requests.find(name) != m_requests.end();
}

std::string SwarmMineHoldBook::name_of(const std::string& name) const
{
    const auto found = m_requests.find(name);
    if (found == m_requests.end()) return {};
    return found->second.name();
}

std::size_t SwarmMineHoldBook::size() const
{
    return m_requests.size();
}

bool SwarmMineHoldBook::mined() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.mined()) return true;
    }
    return kSwarmMineHoldMined;
}

int64_t SwarmMineHoldBook::blocks() const
{
    int64_t total = kSwarmMineHoldBlocks;
    for (const auto& entry : m_requests) {
        total += entry.second.blocks();
    }
    return total;
}

int64_t SwarmMineHoldBook::bytes_moved() const
{
    int64_t total = kSwarmMineHoldBytesMoved;
    for (const auto& entry : m_requests) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmMineHoldBook::broadcast() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.broadcast()) return true;
    }
    return kSwarmMineHoldBroadcast;
}

bool SwarmMineHoldBook::gpu() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmMineHoldGpu;
}

bool SwarmMineHoldBook::store(const std::string& name)
{
    if (contains(name)) return false;
    SwarmMineHoldRecord record = SwarmMineHoldRecord::Make(name);
    if (!SwarmMineHoldRecordUsable(record)) return false;
    m_requests.emplace(name, std::move(record));
    return true;
}

} // namespace modelnet
