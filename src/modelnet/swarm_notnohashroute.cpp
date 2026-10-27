// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohashroute.h>

namespace modelnet {

SwarmNotNoHashRouteResult SwarmNoteNotNoHashRoute(const SwarmNotNoHashRoute& note, std::string& err)
{
    SwarmNotNoHashRouteResult result;
    result.qualified = false;
    result.multihop = false;
    // A hashlock is not a qualified routed network.
    if (note.route_id.empty()) {
        result.code = "ROUTE";
        result.qualified = false;
        result.multihop = false;
        err = "ROUTE";
        return result;
    }
    // A hashlock is unqualified even when the caller did not ask to qualify.
    if (note.hashlock) {
        result.code = "UNQUALIFIED";
        result.qualified = false;
        result.multihop = false;
        err = "UNQUALIFIED";
        return result;
    }
    if (note.want_qualify) {
        result.code = "HELD";
        result.qualified = false;
        result.multihop = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.qualified = false;
    result.multihop = false;
    err.clear();
    return result;
}

} // namespace modelnet
