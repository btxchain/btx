// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routebook/bind.h>

#include <modelnet/swarm_routebook/codes.h>
#include <modelnet/swarm_routebook/hops.h>
#include <modelnet/swarm_routebook/slack.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmRouteBookApplyBind(SwarmRouteBookPath& path, int64_t upstream_delta, std::string& err)
{
    int64_t required = 0;
    const int64_t hop_count = SwarmRouteBookHopCountOf(path);
    if (!SwarmRouteBookDeltaMeetsSlack(hop_count, upstream_delta, required, err)) {
        return false;
    }
    if (upstream_delta < required) {
        err = SWARM_ROUTEBOOK_SLACK;
        return false;
    }
    path.delta_bound = true;
    path.bound_delta = upstream_delta;
    err.clear();
    return true;
}

} // namespace modelnet
