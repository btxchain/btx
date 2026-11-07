// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/quiet.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmAgentRunQuiet::launched() const
{
    return kAgentRunLaunched;
}

bool SwarmAgentRunQuiet::gpu() const
{
    return kAgentRunGpu;
}

int64_t SwarmAgentRunQuiet::bytes_moved() const
{
    return kAgentRunBytesMoved;
}

int64_t SwarmAgentRunQuiet::atoms_moved() const
{
    return kAgentRunAtomsMoved;
}

std::string SwarmAgentRunQuiet::automatic_spend() const
{
    return kAgentRunAutomaticSpend;
}

bool SwarmAgentRunQuiet::broadcast() const
{
    return kAgentRunBroadcast;
}

} // namespace modelnet
