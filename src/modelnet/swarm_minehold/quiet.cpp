// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_minehold/quiet.h>

#include <modelnet/swarm_minehold/limits.h>

namespace modelnet {

int64_t SwarmMineHoldQuiet::bytes_moved() const
{
    return kSwarmMineHoldBytesMoved;
}

bool SwarmMineHoldQuiet::broadcast() const
{
    return kSwarmMineHoldBroadcast;
}

bool SwarmMineHoldQuiet::gpu() const
{
    return kSwarmMineHoldGpu;
}

} // namespace modelnet
