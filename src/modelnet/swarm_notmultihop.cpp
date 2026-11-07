// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmultihop.h>

#include <string>

namespace modelnet {

SwarmNotMultiHopResult SwarmNoteNotMultiHop(const SwarmNotMultiHop& note, std::string& err)
{
    SwarmNotMultiHopResult result;
    result.qualified = false;
    result.multihop = false;
    // A hashlock is not a qualified routed network.
    if (note.route_id.empty() || note.hops < 1) {
        result.code = "ROUTE";
        result.qualified = false;
        result.multihop = false;
        err = "ROUTE";
        return result;
    }
    // More than one hop is refused even when the caller asked to qualify.
    if (note.hops > 1) {
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
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.qualified = false;
    result.multihop = false;
    err.clear();
    return result;
}

} // namespace modelnet
