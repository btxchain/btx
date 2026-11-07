// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/blank.h>

#include <modelnet/swarm_disputestay/codes.h>

namespace modelnet {

bool SwarmDisputeStayBlank::accept(const std::string& dispute, std::string& err) const
{
    if (dispute.empty()) {
        err = kSwarmDisputeStayDispute;
        return false;
    }
    return true;
}

} // namespace modelnet
