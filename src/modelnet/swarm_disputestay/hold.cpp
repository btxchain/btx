// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/hold.h>

#include <modelnet/swarm_disputestay/codes.h>
#include <modelnet/swarm_disputestay/limits.h>

namespace modelnet {

std::string SwarmDisputeStayHold::refusal(const std::string& dispute) const
{
    if (dispute.empty()) return std::string{kSwarmDisputeStayDispute};
    return std::string{kSwarmDisputeStayHeld};
}

bool SwarmDisputeStayHold::settled() const
{
    return kSwarmDisputeStaySettled;
}

} // namespace modelnet
