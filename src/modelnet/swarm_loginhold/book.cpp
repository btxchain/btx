// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_loginhold/book.h>

#include <modelnet/swarm_loginhold/limits.h>

#include <utility>

namespace modelnet {

bool SwarmLoginHoldBook::contains(const std::string& name) const
{
    if (name.empty()) return false;
    return m_requests.find(name) != m_requests.end();
}

std::string SwarmLoginHoldBook::name_of(const std::string& name) const
{
    const auto found = m_requests.find(name);
    if (found == m_requests.end()) return {};
    return found->second.name();
}

std::size_t SwarmLoginHoldBook::size() const
{
    return m_requests.size();
}

bool SwarmLoginHoldBook::logged_in() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.logged_in()) return true;
    }
    return kSwarmLoginHoldLoggedIn;
}

int64_t SwarmLoginHoldBook::bytes_moved() const
{
    int64_t total = kSwarmLoginHoldBytesMoved;
    for (const auto& entry : m_requests) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmLoginHoldBook::gpu() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmLoginHoldGpu;
}

bool SwarmLoginHoldBook::launched() const
{
    for (const auto& entry : m_requests) {
        if (entry.second.launched()) return true;
    }
    return kSwarmLoginHoldLaunched;
}

bool SwarmLoginHoldBook::store(const std::string& name)
{
    if (contains(name)) return false;
    SwarmLoginHoldRecord record = SwarmLoginHoldRecord::Make(name);
    if (!SwarmLoginHoldRecordUsable(record)) return false;
    m_requests.emplace(name, std::move(record));
    return true;
}

} // namespace modelnet
