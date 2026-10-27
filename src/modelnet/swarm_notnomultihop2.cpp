// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomultihop2.h>

#include <string>

namespace modelnet {

SwarmNotNoMultihop2Result SwarmNoteNotNoMultihop2(const SwarmNotNoMultihop2& note, std::string& err)
{
    SwarmNotNoMultihop2Result result;
    result.qualified = false;
    result.multihop = false;
    // A unit note does not qualify a script-enforceable multi-hop route.
    if (note.route_id.empty()) {
        result.code = "ROUTE";
        result.qualified = false;
        result.multihop = false;
        err = "ROUTE";
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
