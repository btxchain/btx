// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routebook/slack.h>

#include <modelnet/swarm_routebook/codes.h>
#include <modelnet/swarm_routebook/limits.h>

#include <cstdint>
#include <limits>
#include <string>

namespace modelnet {

bool SwarmRouteBookRequiredSlack(int64_t hop_count, int64_t& slack)
{
    if (hop_count < 0) {
        slack = 0;
        return false;
    }
    constexpr int64_t margin = kSwarmRouteBookMargin;
    if (hop_count > std::numeric_limits<int64_t>::max() / margin) {
        slack = std::numeric_limits<int64_t>::max();
        return false;
    }
    slack = hop_count * margin;
    return true;
}

bool SwarmRouteBookDeltaMeetsSlack(int64_t hop_count, int64_t upstream_delta, int64_t& required, std::string& err)
{
    if (!SwarmRouteBookRequiredSlack(hop_count, required) || upstream_delta < required) {
        err = SWARM_ROUTEBOOK_SLACK;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
