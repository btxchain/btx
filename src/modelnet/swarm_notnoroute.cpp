// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoroute.h>

#include <string>

namespace modelnet {

SwarmNotNoRouteResult SwarmNoteNotNoRoute(const SwarmNotNoRoute& note, std::string& err)
{
    SwarmNotNoRouteResult result;
    result.reached = false;
    result.qualified = false;
    // A missing route does not qualify a remote host. This note opens
    // no connection and names no address.
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.reached = false;
        result.qualified = false;
        err = "PEER";
        return result;
    }
    if (note.want_reach) {
        result.code = "UNQUALIFIED";
        result.reached = false;
        result.qualified = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.reached = false;
    result.qualified = false;
    err.clear();
    return result;
}

} // namespace modelnet
