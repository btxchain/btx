// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/leader.h>

#include <modelnet/swarm_agentrun/codes.h>
#include <modelnet/swarm_agentrun/lease.h>

#include <string>

namespace modelnet {

bool SwarmAgentRunLeaderGone(const SwarmAgentRunLeases& leases, std::string& err)
{
    if (leases.any()) {
        err = kAgentRunDurable;
        return false;
    }
    err = kAgentRunLost;
    return false;
}

} // namespace modelnet
