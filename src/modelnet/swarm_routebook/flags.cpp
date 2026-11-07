// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routebook/flags.h>

#include <modelnet/swarm_routebook/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmRouteBookFlags::qualified() const
{
    return kSwarmRouteBookQualified;
}

bool SwarmRouteBookFlags::secp_penalty() const
{
    return kSwarmRouteBookSecpPenalty;
}

bool SwarmRouteBookFlags::broadcast() const
{
    return kSwarmRouteBookBroadcast;
}

bool SwarmRouteBookFlags::launched() const
{
    return kSwarmRouteBookLaunched;
}

bool SwarmRouteBookFlags::gpu() const
{
    return kSwarmRouteBookGpu;
}

int64_t SwarmRouteBookFlags::atoms_moved() const
{
    return kSwarmRouteBookAtomsMoved;
}

std::string SwarmRouteBookFlags::automatic_spend() const
{
    return std::string(kSwarmRouteBookAutomaticSpend);
}

bool SwarmRouteBookFlags::signed_ok() const
{
    return kSwarmRouteBookSignedOk;
}

} // namespace modelnet
