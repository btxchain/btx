// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_launchprof/stay.h>

#include <modelnet/swarm_launchprof/codes.h>
#include <modelnet/swarm_launchprof/limits.h>

namespace modelnet {

std::string SwarmLaunchProfileStay::refusal() const
{
    return std::string{kSwarmLaunchProfileHeld};
}

bool SwarmLaunchProfileStay::renamed() const
{
    return kSwarmLaunchProfileRenamed;
}

} // namespace modelnet
