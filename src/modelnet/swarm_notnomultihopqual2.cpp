// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomultihopqual2.h>

#include <string>

namespace modelnet {

SwarmNotNoMultiHopQual2Result SwarmNoteNotNoMultiHopQual2(const SwarmNotNoMultiHopQual2& note, std::string& err)
{
    SwarmNotNoMultiHopQual2Result result;
    result.qualified = false;
    // Multi-hop qualification stays false and this note qualifies nothing.
    if (note.route_id.empty()) {
        result.code = "ROUTE";
        result.qualified = false;
        err = "ROUTE";
        return result;
    }
    if (note.want_qualify) {
        result.code = "HELD";
        result.qualified = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.qualified = false;
    err.clear();
    return result;
}

} // namespace modelnet
