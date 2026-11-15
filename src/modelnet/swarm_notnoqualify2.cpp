// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoqualify2.h>

#include <string>

namespace modelnet {

SwarmNotNoQualify2Result SwarmNoteNotNoQualify2(const SwarmNotNoQualify2& note, std::string& err)
{
    SwarmNotNoQualify2Result result;
    result.qualified = false;
    // qualified stays false on every path. A caller-supplied token rate
    // does not qualify an engine.
    if (note.engine_id.empty()) {
        result.code = "ENGINE";
        result.qualified = false;
        err = "ENGINE";
        return result;
    }
    if (note.caller_rate) {
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
