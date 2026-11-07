// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routebook/hops.h>

#include <modelnet/swarm_routebook/codes.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>

namespace modelnet {

bool SwarmRouteBookNamesPresent(const std::string& route, const std::string& hop, std::string& err)
{
    if (route.empty() || hop.empty()) {
        err = SWARM_ROUTEBOOK_ROUTE;
        return false;
    }
    return true;
}

int64_t SwarmRouteBookHopCountOf(const SwarmRouteBookPath& path)
{
    const std::size_t count = path.hops.size();
    if (count > static_cast<std::size_t>(std::numeric_limits<int64_t>::max())) {
        return std::numeric_limits<int64_t>::max();
    }
    return static_cast<int64_t>(count);
}

const SwarmRouteBookHopRecord* SwarmRouteBookFindHop(const SwarmRouteBookPath& path, const std::string& hop)
{
    for (const SwarmRouteBookHopRecord& record : path.hops) {
        if (record.hop == hop) {
            return &record;
        }
    }
    return nullptr;
}

bool SwarmRouteBookAppendHop(SwarmRouteBookPath& path, const std::string& hop, int64_t cltv_expiry, std::string& err)
{
    if (hop.empty()) {
        err = SWARM_ROUTEBOOK_ROUTE;
        return false;
    }
    if (SwarmRouteBookFindHop(path, hop) != nullptr) {
        err = SWARM_ROUTEBOOK_REPLAY;
        return false;
    }
    if (cltv_expiry < 0) {
        err = SWARM_ROUTEBOOK_EXPIRY;
        return false;
    }
    SwarmRouteBookHopRecord record;
    record.hop = hop;
    record.cltv_expiry = cltv_expiry;
    path.hops.push_back(std::move(record));
    err.clear();
    return true;
}

} // namespace modelnet
