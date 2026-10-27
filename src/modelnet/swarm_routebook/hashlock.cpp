// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routebook/hashlock.h>

#include <modelnet/swarm_routebook/codes.h>
#include <modelnet/swarm_routebook/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmRouteBookClassifyHashlock(bool route_known, int64_t preimage_len, std::string& err)
{
    if (!route_known) {
        err = SWARM_ROUTEBOOK_ROUTE;
        return false;
    }
    if (preimage_len != kSwarmRouteBookPreimageLen) {
        err = SWARM_ROUTEBOOK_PREIMAGE;
        return false;
    }
    // 32 bytes is the hashlock length. A digest match is not a settled route.
    err = SWARM_ROUTEBOOK_NOT_ROUTE;
    return false;
}

} // namespace modelnet
