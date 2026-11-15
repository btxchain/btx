// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandgate/quiet.h>

#include <modelnet/swarm_islandgate/limits.h>

namespace modelnet {

int64_t SwarmIslandGateQuiet::bytes_moved() const
{
    return kSwarmIslandGateBytesMoved;
}

bool SwarmIslandGateQuiet::gpu() const
{
    return kSwarmIslandGateGpu;
}

bool SwarmIslandGateQuiet::launched() const
{
    return kSwarmIslandGateLaunched;
}

} // namespace modelnet
