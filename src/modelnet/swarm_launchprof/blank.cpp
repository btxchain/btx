// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_launchprof/blank.h>

#include <modelnet/swarm_launchprof/codes.h>

namespace modelnet {

bool SwarmLaunchProfileBlank::accept(const std::string& name, std::string& err) const
{
    if (name.empty()) {
        err = kSwarmLaunchProfileProfile;
        return false;
    }
    return true;
}

} // namespace modelnet
