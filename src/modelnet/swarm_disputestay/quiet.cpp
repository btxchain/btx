// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/quiet.h>

#include <modelnet/swarm_disputestay/limits.h>

namespace modelnet {

bool SwarmDisputeStayQuiet::broadcast() const
{
    return kSwarmDisputeStayBroadcast;
}

bool SwarmDisputeStayQuiet::mined() const
{
    return kSwarmDisputeStayMined;
}

int64_t SwarmDisputeStayQuiet::bytes_moved() const
{
    return kSwarmDisputeStayBytesMoved;
}

std::string SwarmDisputeStayQuiet::automatic_spend() const
{
    return std::string{kSwarmDisputeStayAutomaticSpend};
}

} // namespace modelnet
