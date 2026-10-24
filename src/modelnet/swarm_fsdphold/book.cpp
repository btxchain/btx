// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fsdphold/book.h>

#include <modelnet/swarm_fsdphold/limits.h>

#include <utility>

namespace modelnet {

bool SwarmFsdpHoldBook::contains(const std::string& name) const
{
    if (name.empty()) return false;
    return m_requests.find(name) != m_requests.end();
}

std::string SwarmFsdpHoldBook::name_of(const std::string& name) const
{
    const auto found = m_requests.find(name);
    if (found == m_requests.end()) return {};
    return found->second.name();
}

std::size_t SwarmFsdpHoldBook::size() const
{
    return m_requests.size();
}

bool SwarmFsdpHoldBook::running() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.running()) return true;
    }
    return kSwarmFsdpHoldRunning;
}

int64_t SwarmFsdpHoldBook::bytes_moved() const
{
    int64_t total = kSwarmFsdpHoldBytesMoved;
    for (const auto& entry : m_requests) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmFsdpHoldBook::gpu() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmFsdpHoldGpu;
}

bool SwarmFsdpHoldBook::launched() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.launched()) return true;
    }
    return kSwarmFsdpHoldLaunched;
}

bool SwarmFsdpHoldBook::store(const std::string& name)
{
    if (contains(name)) return false;
    SwarmFsdpHoldRecord record = SwarmFsdpHoldRecord::Make(name);
    if (!SwarmFsdpHoldRecordUsable(record)) return false;
    m_requests.emplace(name, std::move(record));
    return true;
}

} // namespace modelnet
