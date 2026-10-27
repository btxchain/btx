// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mixedhold/book.h>

#include <modelnet/swarm_mixedhold/limits.h>

#include <utility>

namespace modelnet {

bool SwarmMixedHoldBook::contains(const std::string& name) const
{
    if (name.empty()) return false;
    return m_requests.find(name) != m_requests.end();
}

std::string SwarmMixedHoldBook::name_of(const std::string& name) const
{
    const auto found = m_requests.find(name);
    if (found == m_requests.end()) return {};
    return found->second.name();
}

std::size_t SwarmMixedHoldBook::size() const
{
    return m_requests.size();
}

bool SwarmMixedHoldBook::running() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.running()) return true;
    }
    return kSwarmMixedHoldRunning;
}

int64_t SwarmMixedHoldBook::bytes_moved() const
{
    int64_t total = kSwarmMixedHoldBytesMoved;
    for (const auto& entry : m_requests) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmMixedHoldBook::gpu() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmMixedHoldGpu;
}

bool SwarmMixedHoldBook::launched() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.launched()) return true;
    }
    return kSwarmMixedHoldLaunched;
}

bool SwarmMixedHoldBook::store(const std::string& name)
{
    if (contains(name)) return false;
    SwarmMixedHoldRecord record = SwarmMixedHoldRecord::Make(name);
    if (!SwarmMixedHoldRecordUsable(record)) return false;
    m_requests.emplace(name, std::move(record));
    return true;
}

} // namespace modelnet
