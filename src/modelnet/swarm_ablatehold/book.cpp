// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ablatehold/book.h>

#include <modelnet/swarm_ablatehold/limits.h>

#include <utility>

namespace modelnet {

bool SwarmAblateHoldBook::contains(const std::string& name) const
{
    if (name.empty()) return false;
    return m_requests.find(name) != m_requests.end();
}

std::string SwarmAblateHoldBook::name_of(const std::string& name) const
{
    const auto found = m_requests.find(name);
    if (found == m_requests.end()) return {};
    return found->second.name();
}

std::size_t SwarmAblateHoldBook::size() const
{
    return m_requests.size();
}

bool SwarmAblateHoldBook::published() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.published()) return true;
    }
    return kSwarmAblateHoldPublished;
}

int64_t SwarmAblateHoldBook::bytes_moved() const
{
    int64_t total = kSwarmAblateHoldBytesMoved;
    for (const auto& entry : m_requests) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmAblateHoldBook::gpu() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmAblateHoldGpu;
}

bool SwarmAblateHoldBook::launched() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.launched()) return true;
    }
    return kSwarmAblateHoldLaunched;
}

bool SwarmAblateHoldBook::store(const std::string& name)
{
    if (contains(name)) return false;
    SwarmAblateHoldRecord record = SwarmAblateHoldRecord::Make(name);
    if (!SwarmAblateHoldRecordUsable(record)) return false;
    m_requests.emplace(name, std::move(record));
    return true;
}

} // namespace modelnet
