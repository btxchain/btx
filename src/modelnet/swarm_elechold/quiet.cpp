// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/quiet.h>

#include <modelnet/swarm_elechold/limits.h>

namespace modelnet {

std::string SwarmElecHoldQuiet::automatic_spend() const
{
    return std::string{kSwarmElecHoldAutomaticSpend};
}

bool SwarmElecHoldQuiet::broadcast() const
{
    return kSwarmElecHoldBroadcast;
}

int64_t SwarmElecHoldQuiet::bytes_moved() const
{
    return kSwarmElecHoldBytesMoved;
}

bool SwarmElecHoldQuiet::gpu() const
{
    return kSwarmElecHoldGpu;
}

} // namespace modelnet
