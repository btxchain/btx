// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notscripthop.h>

#include <string>

namespace modelnet {

SwarmNotScriptHopResult SwarmNoteNotScriptHop(const SwarmNotScriptHop& note, std::string& err)
{
    SwarmNotScriptHopResult result;
    result.qualified = false;
    result.multihop = false;
    result.broadcast = false;
    // This note does not build a script, settle, or broadcast.
    // Multi-hop stays unqualified.
    if (note.invoice_id.empty()) {
        result.code = "INVOICE";
        result.qualified = false;
        result.multihop = false;
        result.broadcast = false;
        err = "INVOICE";
        return result;
    }
    if (note.want_qualify) {
        result.code = "UNQUALIFIED";
        result.qualified = false;
        result.multihop = false;
        result.broadcast = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.qualified = false;
    result.multihop = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
