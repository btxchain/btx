// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoscriptroute2.h>

#include <string>

namespace modelnet {

SwarmNotNoScriptRoute2Result SwarmNoteNotNoScriptRoute2(const SwarmNotNoScriptRoute2& note, std::string& err)
{
    SwarmNotNoScriptRoute2Result result;
    result.qualified = false;
    // A hashlock is not a script-qualified route.
    if (note.route_id.empty()) {
        result.code = "ROUTE";
        result.qualified = false;
        err = "ROUTE";
        return result;
    }
    // A hashlock is not a script-qualified route, even when the caller did not ask to qualify.
    if (note.hashlock) {
        result.code = "NOT_QUALIFIED";
        result.qualified = false;
        err = "NOT_QUALIFIED";
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
