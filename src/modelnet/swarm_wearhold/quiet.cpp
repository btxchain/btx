// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearhold/quiet.h>

#include <modelnet/swarm_wearhold/limits.h>

namespace modelnet {

std::string SwarmWearHoldQuiet::automatic_spend() const
{
    return std::string{kSwarmWearHoldAutomaticSpend};
}

bool SwarmWearHoldQuiet::broadcast() const
{
    return kSwarmWearHoldBroadcast;
}

int64_t SwarmWearHoldQuiet::bytes_moved() const
{
    return kSwarmWearHoldBytesMoved;
}

bool SwarmWearHoldQuiet::gpu() const
{
    return kSwarmWearHoldGpu;
}

} // namespace modelnet
