// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/floor.h>

#include <modelnet/swarm_generation/limits.h>

namespace modelnet {

bool SwarmGenerationFloor::launched() const
{
    return false;
}

bool SwarmGenerationFloor::gpu() const
{
    return false;
}

int64_t SwarmGenerationFloor::bytes_moved() const
{
    return kSwarmGenerationBytesMoved;
}

int64_t SwarmGenerationFloor::atoms_moved() const
{
    return kSwarmGenerationAtomsMoved;
}

const std::string& SwarmGenerationFloor::automatic_spend() const
{
    return m_automatic_spend;
}

bool SwarmGenerationFloor::broadcast() const
{
    return false;
}

bool SwarmGenerationFloor::realm_promoted() const
{
    return false;
}

bool SwarmGenerationFloor::exact_replay_admitted() const
{
    return false;
}

bool SwarmGenerationFloor::running() const
{
    return false;
}

} // namespace modelnet
