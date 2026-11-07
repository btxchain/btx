// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/height.h>

#include <modelnet/swarm_adminhold/codes.h>
#include <modelnet/swarm_adminhold/limits.h>

namespace modelnet {

bool SwarmAdminHoldHeight::accept(int64_t refund_height, std::string& err) const
{
    if (refund_height < kSwarmAdminHoldMinHeight) {
        err = kSwarmAdminHoldHeight;
        return false;
    }
    return true;
}

} // namespace modelnet
