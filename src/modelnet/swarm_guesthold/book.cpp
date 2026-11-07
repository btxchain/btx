// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_guesthold/book.h>

#include <modelnet/swarm_guesthold/limits.h>

#include <utility>

namespace modelnet {

bool SwarmGuestHoldBook::contains(const std::string& name) const
{
    if (name.empty()) return false;
    return m_checks.find(name) != m_checks.end();
}

std::string SwarmGuestHoldBook::name_of(const std::string& name) const
{
    const auto found = m_checks.find(name);
    if (found == m_checks.end()) return {};
    return found->second.name();
}

std::size_t SwarmGuestHoldBook::size() const
{
    return m_checks.size();
}

bool SwarmGuestHoldBook::passed() const
{
    for (const auto& entry : m_checks) {
        if (entry.second.passed()) return true;
    }
    return kSwarmGuestHoldPassed;
}

bool SwarmGuestHoldBook::logged_in() const
{
    for (const auto& entry : m_checks) {
        if (entry.second.logged_in()) return true;
    }
    return kSwarmGuestHoldLoggedIn;
}

int64_t SwarmGuestHoldBook::bytes_moved() const
{
    int64_t total = kSwarmGuestHoldBytesMoved;
    for (const auto& entry : m_checks) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmGuestHoldBook::gpu() const
{
    for (const auto& entry : m_checks) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmGuestHoldGpu;
}

bool SwarmGuestHoldBook::launched() const
{
    for (const auto& entry : m_checks) {
        if (entry.second.launched()) return true;
    }
    return kSwarmGuestHoldLaunched;
}

bool SwarmGuestHoldBook::store(const std::string& name)
{
    if (contains(name)) return false;
    SwarmGuestHoldRecord record = SwarmGuestHoldRecord::Make(name);
    if (!SwarmGuestHoldRecordUsable(record)) return false;
    m_checks.emplace(name, std::move(record));
    return true;
}

} // namespace modelnet
