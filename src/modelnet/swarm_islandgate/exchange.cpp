// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandgate/exchange.h>

#include <modelnet/swarm_islandgate/codes.h>
#include <modelnet/swarm_islandgate/limits.h>

namespace modelnet {

bool SwarmIslandGateExchange::Exchange(std::string& err)
{
    err = kSwarmIslandGateHeld;
    return false;
}

bool SwarmIslandGateExchange::exchanged() const
{
    return kSwarmIslandGateExchanged;
}

} // namespace modelnet
