// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentexec/quiet.h>

#include <modelnet/swarm_agentexec/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmAgentExecQuiet::launched() const
{
    return kSwarmAgentExecLaunched;
}

bool SwarmAgentExecQuiet::connected() const
{
    return kSwarmAgentExecConnected;
}

bool SwarmAgentExecQuiet::gpu() const
{
    return kSwarmAgentExecGpu;
}

bool SwarmAgentExecQuiet::broadcast() const
{
    return kSwarmAgentExecBroadcast;
}

int64_t SwarmAgentExecQuiet::atoms_moved() const
{
    return kSwarmAgentExecAtomsMoved;
}

std::string SwarmAgentExecQuiet::automatic_spend() const
{
    return std::string{kSwarmAgentExecAutomaticSpend};
}

} // namespace modelnet
