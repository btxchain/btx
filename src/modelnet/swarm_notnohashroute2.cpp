// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohashroute2.h>

#include <string>

namespace modelnet {

SwarmNotNoHashRoute2Result SwarmNoteNotNoHashRoute2(const SwarmNotNoHashRoute2& note, std::string& err)
{
    SwarmNotNoHashRoute2Result result;
    result.routed = false;
    // A hashlock is not a route.
    if (note.route_id.empty()) {
        result.code = "ROUTE";
        result.routed = false;
        err = "ROUTE";
        return result;
    }
    // A hashlock is not a route, even when the caller did not ask to route.
    if (note.hashlock) {
        result.code = "NOT_ROUTE";
        result.routed = false;
        err = "NOT_ROUTE";
        return result;
    }
    if (note.want_route) {
        result.code = "HELD";
        result.routed = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.routed = false;
    err.clear();
    return result;
}

} // namespace modelnet
