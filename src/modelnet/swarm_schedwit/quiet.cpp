// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedwit/quiet.h>

#include <modelnet/swarm_schedwit/limits.h>

#include <string>

namespace modelnet {

int64_t SwarmSchedWitnessQuiet::atoms_moved() const
{
    return kSwarmSchedWitnessAtomsMoved;
}

std::string SwarmSchedWitnessQuiet::automatic_spend() const
{
    return std::string{kSwarmSchedWitnessAutomaticSpend};
}

bool SwarmSchedWitnessQuiet::broadcast() const
{
    return kSwarmSchedWitnessBroadcast;
}

int64_t SwarmSchedWitnessQuiet::bytes_moved() const
{
    return kSwarmSchedWitnessBytesMoved;
}

bool SwarmSchedWitnessQuiet::gpu() const
{
    return kSwarmSchedWitnessGpu;
}

} // namespace modelnet
