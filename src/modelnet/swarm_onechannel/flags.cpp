// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_onechannel/flags.h>

#include <modelnet/swarm_onechannel/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmOneChannelFlags::network_opened() const
{
    return kSwarmOneChannelNetworkOpened;
}

bool SwarmOneChannelFlags::broadcast() const
{
    return kSwarmOneChannelBroadcast;
}

bool SwarmOneChannelFlags::launched() const
{
    return kSwarmOneChannelLaunched;
}

bool SwarmOneChannelFlags::gpu() const
{
    return kSwarmOneChannelGpu;
}

int64_t SwarmOneChannelFlags::atoms_moved() const
{
    return kSwarmOneChannelAtomsMoved;
}

std::string SwarmOneChannelFlags::automatic_spend() const
{
    return std::string(kSwarmOneChannelAutomaticSpend);
}

} // namespace modelnet
