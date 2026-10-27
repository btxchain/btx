// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_passhold/book.h>

#include <modelnet/swarm_passhold/limits.h>

#include <utility>

namespace modelnet {

bool SwarmPassHoldBook::contains(const std::string& name) const
{
    if (name.empty()) return false;
    return m_requests.find(name) != m_requests.end();
}

std::string SwarmPassHoldBook::name_of(const std::string& name) const
{
    const auto found = m_requests.find(name);
    if (found == m_requests.end()) return {};
    return found->second.name();
}

std::size_t SwarmPassHoldBook::size() const
{
    return m_requests.size();
}

bool SwarmPassHoldBook::started() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.started()) return true;
    }
    return kSwarmPassHoldStarted;
}

bool SwarmPassHoldBook::passed() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.passed()) return true;
    }
    return kSwarmPassHoldPassed;
}

int64_t SwarmPassHoldBook::bytes_moved() const
{
    int64_t total = kSwarmPassHoldBytesMoved;
    for (const auto& entry : m_requests) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmPassHoldBook::gpu() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmPassHoldGpu;
}

bool SwarmPassHoldBook::launched() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.launched()) return true;
    }
    return kSwarmPassHoldLaunched;
}

bool SwarmPassHoldBook::store(const std::string& name)
{
    if (contains(name)) return false;
    SwarmPassHoldRecord record = SwarmPassHoldRecord::Make(name);
    if (!SwarmPassHoldRecordUsable(record)) return false;
    m_requests.emplace(name, std::move(record));
    return true;
}

} // namespace modelnet
