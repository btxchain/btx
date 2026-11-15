// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notroute.h>

namespace modelnet {

SwarmNotRouteResult SwarmNoteNotRoute(const SwarmNotRoute& note, std::string& err)
{
    SwarmNotRouteResult result;
    result.handled = false;
    result.broadcast = false;
    result.multihop = false;
    if (note.route_id.empty()) {
        result.code = "ROUTE";
        result.handled = false;
        result.broadcast = false;
        result.multihop = false;
        err = "ROUTE";
        return result;
    }
    if (note.want_handle) {
        result.code = "UNQUALIFIED";
        result.handled = false;
        result.broadcast = false;
        result.multihop = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.handled = false;
    result.broadcast = false;
    result.multihop = false;
    err.clear();
    return result;
}

} // namespace modelnet
