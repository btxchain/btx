// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohashlock2.h>

namespace modelnet {

SwarmNotNoHashlock2Result SwarmNoteNotNoHashlock2(const SwarmNotNoHashlock2& note, std::string& err)
{
    SwarmNotNoHashlock2Result result;
    result.routed = false;
    result.bytes_moved = false;
    // A hashlock is not a route.
    if (note.route_id.empty()) {
        result.code = "ROUTE";
        result.routed = false;
        result.bytes_moved = false;
        err = "ROUTE";
        return result;
    }
    // A hashlock is not a route even when the caller did not ask to route.
    if (note.hashlock) {
        result.code = "NOT_ROUTE";
        result.routed = false;
        result.bytes_moved = false;
        err = "NOT_ROUTE";
        return result;
    }
    if (note.want_route) {
        result.code = "HELD";
        result.routed = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.routed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
