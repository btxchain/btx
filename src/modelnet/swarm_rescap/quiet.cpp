// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rescap/quiet.h>

#include <modelnet/swarm_rescap/limits.h>

namespace modelnet {

int64_t SwarmResCapQuiet::bytes_moved() const
{
    return kSwarmResCapBytesMoved;
}

bool SwarmResCapQuiet::gpu() const
{
    return kSwarmResCapGpu;
}

bool SwarmResCapQuiet::launched() const
{
    return kSwarmResCapLaunched;
}

} // namespace modelnet
