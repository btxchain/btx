// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchhold/release.h>

#include <modelnet/swarm_watchhold/codes.h>

namespace modelnet {

bool SwarmWatchHoldRelease(std::string& err)
{
    err = kSwarmWatchHoldHeld;
    return false;
}

} // namespace modelnet
