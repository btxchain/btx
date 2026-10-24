// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/freeze.h>

#include <modelnet/swarm_adminhold/codes.h>

namespace modelnet {

bool SwarmAdminHoldFreeze::refuse(const SwarmAdminHoldBook& book, const std::string& channel, std::string& err) const
{
    if (!book.contains(channel)) {
        err = kSwarmAdminHoldChannel;
        return false;
    }
    err = kSwarmAdminHoldHeld;
    return false;
}

} // namespace modelnet
