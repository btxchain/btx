// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/quiet.h>

#include <modelnet/swarm_adminhold/limits.h>

namespace modelnet {

bool SwarmAdminHoldQuiet::broadcast() const
{
    return kSwarmAdminHoldBroadcast;
}

bool SwarmAdminHoldQuiet::mined() const
{
    return kSwarmAdminHoldMined;
}

int64_t SwarmAdminHoldQuiet::bytes_moved() const
{
    return kSwarmAdminHoldBytesMoved;
}

std::string SwarmAdminHoldQuiet::automatic_spend() const
{
    return std::string{kSwarmAdminHoldAutomaticSpend};
}

} // namespace modelnet
