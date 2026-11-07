// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohashlock.h>

#include <string>

namespace modelnet {

SwarmNotNoHashlockResult SwarmNoteNotNoHashlock(const SwarmNotNoHashlock& note, std::string& err)
{
    SwarmNotNoHashlockResult result;
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
    if (note.hashlock_only) {
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
