// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/quiet.h>

#include <modelnet/swarm_tokgate/limits.h>

#include <cstdint>

namespace modelnet {

bool SwarmTokenGateQuiet::running() const
{
    return kSwarmTokenGateRunning;
}

bool SwarmTokenGateQuiet::launched() const
{
    return kSwarmTokenGateLaunched;
}

bool SwarmTokenGateQuiet::gpu() const
{
    return kSwarmTokenGateGpu;
}

int64_t SwarmTokenGateQuiet::bytes_moved() const
{
    return kSwarmTokenGateBytesMoved;
}

} // namespace modelnet
