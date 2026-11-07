// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/quiet.h>

#include <modelnet/swarm_execnbhd/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmExecNbhdQuiet::connected() const
{
    return kSwarmExecNbhdConnected;
}

bool SwarmExecNbhdQuiet::socket_opened() const
{
    return kSwarmExecNbhdSocketOpened;
}

bool SwarmExecNbhdQuiet::launched() const
{
    return kSwarmExecNbhdLaunched;
}

bool SwarmExecNbhdQuiet::gpu() const
{
    return kSwarmExecNbhdGpu;
}

bool SwarmExecNbhdQuiet::broadcast() const
{
    return kSwarmExecNbhdBroadcast;
}

int64_t SwarmExecNbhdQuiet::bytes_moved() const
{
    return kSwarmExecNbhdBytesMoved;
}

std::string SwarmExecNbhdQuiet::automatic_spend() const
{
    return kSwarmExecNbhdAutomaticSpend;
}

int64_t SwarmExecNbhdQuiet::atoms_moved() const
{
    return kSwarmExecNbhdAtomsMoved;
}

} // namespace modelnet
