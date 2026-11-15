// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/book.h>

#include <modelnet/swarm_disputestay/limits.h>

#include <utility>

namespace modelnet {

bool SwarmDisputeStayBook::contains(const std::string& dispute) const
{
    if (dispute.empty()) return false;
    return m_disputes.find(dispute) != m_disputes.end();
}

std::string SwarmDisputeStayBook::dispute_of(const std::string& dispute) const
{
    const auto found = m_disputes.find(dispute);
    if (found == m_disputes.end()) return {};
    return found->second.dispute();
}

std::size_t SwarmDisputeStayBook::size() const
{
    return m_disputes.size();
}

int64_t SwarmDisputeStayBook::atoms_of(const std::string& dispute) const
{
    const auto found = m_disputes.find(dispute);
    if (found == m_disputes.end()) return kSwarmDisputeStayAtomsMoved;
    return found->second.atoms_moved();
}

bool SwarmDisputeStayBook::settled() const
{
    for (const auto& entry : m_disputes) {
        if (entry.second.settled()) return true;
    }
    return kSwarmDisputeStaySettled;
}

int64_t SwarmDisputeStayBook::atoms_moved() const
{
    int64_t total = kSwarmDisputeStayAtomsMoved;
    for (const auto& entry : m_disputes) {
        total += entry.second.atoms_moved();
    }
    return total;
}

int64_t SwarmDisputeStayBook::bytes_moved() const
{
    int64_t total = kSwarmDisputeStayBytesMoved;
    for (const auto& entry : m_disputes) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmDisputeStayBook::broadcast() const
{
    for (const auto& entry : m_disputes) {
        if (entry.second.broadcast()) return true;
    }
    return kSwarmDisputeStayBroadcast;
}

bool SwarmDisputeStayBook::mined() const
{
    for (const auto& entry : m_disputes) {
        if (entry.second.mined()) return true;
    }
    return kSwarmDisputeStayMined;
}

bool SwarmDisputeStayBook::store(const std::string& dispute)
{
    if (contains(dispute)) return false;
    SwarmDisputeStayRecord record = SwarmDisputeStayRecord::Make(dispute);
    if (!SwarmDisputeStayRecordUsable(record)) return false;
    m_disputes.emplace(dispute, std::move(record));
    return true;
}

} // namespace modelnet
