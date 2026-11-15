// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot/book.h>

#include <modelnet/swarm_holdrot/limits.h>

#include <utility>

namespace modelnet {

bool SwarmHoldoutRotateBook::contains(const std::string& holdout) const
{
    if (holdout.empty()) return false;
    return m_holdouts.find(holdout) != m_holdouts.end();
}

std::string SwarmHoldoutRotateBook::holdout_of(const std::string& holdout) const
{
    const auto found = m_holdouts.find(holdout);
    if (found == m_holdouts.end()) return {};
    return found->second.holdout();
}

std::size_t SwarmHoldoutRotateBook::size() const
{
    return m_holdouts.size();
}

bool SwarmHoldoutRotateBook::rotated() const
{
    for (const auto& entry : m_holdouts) {
        if (entry.second.rotated()) return true;
    }
    return kSwarmHoldoutRotateRotated;
}

int64_t SwarmHoldoutRotateBook::bytes_moved() const
{
    int64_t total = kSwarmHoldoutRotateBytesMoved;
    for (const auto& entry : m_holdouts) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmHoldoutRotateBook::gpu() const
{
    for (const auto& entry : m_holdouts) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmHoldoutRotateGpu;
}

bool SwarmHoldoutRotateBook::launched() const
{
    for (const auto& entry : m_holdouts) {
        if (entry.second.launched()) return true;
    }
    return kSwarmHoldoutRotateLaunched;
}

bool SwarmHoldoutRotateBook::store(const std::string& holdout)
{
    if (contains(holdout)) return false;
    SwarmHoldoutRotateRecord record = SwarmHoldoutRotateRecord::Make(holdout);
    if (!SwarmHoldoutRotateRecordUsable(record)) return false;
    m_holdouts.emplace(holdout, std::move(record));
    return true;
}

} // namespace modelnet
