// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/lease.h>

#include <modelnet/swarm_agents/codes.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmAgentLeaseBook::Grant(const std::string& lease, int64_t until, int64_t now, std::string& err)
{
    if (lease.empty()) {
        err = kAgentLease;
        return false;
    }
    if (until < now) {
        err = kAgentExpired;
        return false;
    }
    m_admitted = true;
    m_lease = lease;
    m_until = until;
    err.clear();
    return true;
}

bool SwarmAgentLeaseBook::admitted() const
{
    return m_admitted;
}

uint64_t SwarmAgentLeaseBook::epoch() const
{
    return m_epoch;
}

const std::string& SwarmAgentLeaseBook::lease_id() const
{
    return m_lease;
}

int64_t SwarmAgentLeaseBook::until() const
{
    return m_until;
}

bool SwarmAgentLeaseBook::Matches(uint64_t epoch, std::string& err) const
{
    if (epoch != m_epoch) {
        err = kAgentStaleEpoch;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
