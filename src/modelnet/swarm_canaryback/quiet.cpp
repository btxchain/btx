// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryback/quiet.h>

#include <modelnet/swarm_canaryback/limits.h>

namespace modelnet {

int64_t SwarmCanaryBackQuiet::bytes_moved() const
{
    return kSwarmCanaryBackBytesMoved;
}

int64_t SwarmCanaryBackQuiet::blocks() const
{
    return kSwarmCanaryBackBlocks;
}

bool SwarmCanaryBackQuiet::gpu() const
{
    return kSwarmCanaryBackGpu;
}

bool SwarmCanaryBackQuiet::graduated() const
{
    return kSwarmCanaryBackGraduated;
}

bool SwarmCanaryBackQuiet::mined() const
{
    return kSwarmCanaryBackMined;
}

} // namespace modelnet
