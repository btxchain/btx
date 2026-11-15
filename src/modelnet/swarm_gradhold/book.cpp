// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradhold/book.h>

#include <modelnet/swarm_gradhold/limits.h>

#include <utility>

namespace modelnet {

bool SwarmGradHoldBook::contains(const std::string& update_id) const
{
    if (update_id.empty()) return false;
    return m_updates.find(update_id) != m_updates.end();
}

std::string SwarmGradHoldBook::update_id_of(const std::string& update_id) const
{
    const auto found = m_updates.find(update_id);
    if (found == m_updates.end()) return {};
    return found->second.update_id();
}

std::size_t SwarmGradHoldBook::size() const
{
    return m_updates.size();
}

bool SwarmGradHoldBook::exported() const
{
    for (const auto& entry : m_updates) {
        if (entry.second.exported()) return true;
    }
    return kSwarmGradHoldExported;
}

int64_t SwarmGradHoldBook::bytes_moved() const
{
    int64_t total = kSwarmGradHoldBytesMoved;
    for (const auto& entry : m_updates) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmGradHoldBook::gpu() const
{
    for (const auto& entry : m_updates) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmGradHoldGpu;
}

bool SwarmGradHoldBook::launched() const
{
    for (const auto& entry : m_updates) {
        if (entry.second.launched()) return true;
    }
    return kSwarmGradHoldLaunched;
}

bool SwarmGradHoldBook::store(const std::string& update_id)
{
    if (contains(update_id)) return false;
    SwarmGradHoldRecord record = SwarmGradHoldRecord::Make(update_id);
    if (!SwarmGradHoldRecordUsable(record)) return false;
    m_updates.emplace(update_id, std::move(record));
    return true;
}

} // namespace modelnet
