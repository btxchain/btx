// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobodycap2.h>

namespace modelnet {

SwarmNotNoBodyCap2Result SwarmNoteNotNoBodyCap2(const SwarmNotNoBodyCap2& note, std::string& err)
{
    // A body stays capped at 33554432 bytes.
    SwarmNotNoBodyCap2Result result;
    result.raised = false;
    result.bytes = 33554432;
    if (note.body_id.empty()) {
        result.code = "BODY";
        result.raised = false;
        result.bytes = 33554432;
        err = "BODY";
        return result;
    }
    if (note.want_raise) {
        result.code = "HELD";
        result.raised = false;
        result.bytes = 33554432;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.raised = false;
    result.bytes = 33554432;
    err.clear();
    return result;
}

} // namespace modelnet
