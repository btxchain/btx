// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmhq.h>

namespace modelnet {

SwarmNotMhqResult SwarmNoteNotMhq(const SwarmNotMhq& note, std::string& err)
{
    SwarmNotMhqResult result;
    result.qualified = false;
    result.multihop = false;
    // MultiHopQualified stays false. This note does not settle or broadcast.
    if (note.route_id.empty()) {
        result.code = "ROUTE";
        result.qualified = false;
        result.multihop = false;
        err = "ROUTE";
        return result;
    }
    // More than one hop is unqualified even when the caller did not ask to qualify.
    if (note.hop_count > 1) {
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
