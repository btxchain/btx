// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_launchprof/quiet.h>

#include <modelnet/swarm_launchprof/limits.h>

namespace modelnet {

int64_t SwarmLaunchProfileQuiet::bytes_moved() const
{
    return kSwarmLaunchProfileBytesMoved;
}

bool SwarmLaunchProfileQuiet::gpu() const
{
    return kSwarmLaunchProfileGpu;
}

bool SwarmLaunchProfileQuiet::launched() const
{
    return kSwarmLaunchProfileLaunched;
}

} // namespace modelnet
