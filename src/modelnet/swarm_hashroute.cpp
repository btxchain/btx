// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hashroute.h>

namespace modelnet {

// A hashlock is not a route.
SwarmHashRouteResult SwarmNoteHashRoute(const SwarmHashRoute& route, std::string& err)
{
    SwarmHashRouteResult result;
    result.routed = false;
    result.bytes_moved = 0;

    if (route.route_id.empty()) {
        result.code = "ROUTE";
        err = "ROUTE";
        return result;
    }
    if (route.hashlock) {
        result.code = "NOT_ROUTE";
        err = "NOT_ROUTE";
        return result;
    }
    if (route.want_route) {
        result.code = "HELD";
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
