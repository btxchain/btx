// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/channel.h>

#include <modelnet/swarm_adminhold/codes.h>

namespace modelnet {

bool SwarmAdminHoldChannel::accept(const std::string& channel, std::string& err) const
{
    if (channel.empty()) {
        err = kSwarmAdminHoldChannel;
        return false;
    }
    return true;
}

} // namespace modelnet
