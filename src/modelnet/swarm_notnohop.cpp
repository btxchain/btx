// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohop.h>

namespace modelnet {

SwarmNotNoHopResult SwarmNoteNotNoHop(const SwarmNotNoHop& note, std::string& err)
{
    SwarmNotNoHopResult result;
    result.qualified = false;
    result.multihop = false;
    // More than one hop is not a qualified route.
    if (note.route_id.empty()) {
        result.code = "ROUTE";
        result.qualified = false;
        result.multihop = false;
        err = "ROUTE";
        return result;
    }
    // More than one hop is unqualified even when the caller did not ask to qualify.
    if (note.hops > 1) {
        result.code = "UNQUALIFIED";
        result.qualified = false;
        result.multihop = false;
        err = "UNQUALIFIED";
        return result;
    }
    if (note.want_qualify) {
        result.code = "UNQUALIFIED";
        result.qualified = false;
        result.multihop = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.qualified = false;
    result.multihop = false;
    err.clear();
    return result;
}

} // namespace modelnet
