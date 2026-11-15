// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomcp.h>

namespace modelnet {

SwarmNotNoMcpResult SwarmNoteNotNoMcp(const SwarmNotNoMcp& note, std::string& err)
{
    // This note makes no outbound tool call.
    if (note.tool_id.empty()) {
        err = "TOOL";
        return SwarmNotNoMcpResult{"TOOL", false, false};
    }
    if (note.want_call) {
        err = "NOT_CALLED";
        return SwarmNotNoMcpResult{"NOT_CALLED", false, false};
    }
    err.clear();
    return SwarmNotNoMcpResult{"NOTED", false, false};
}

} // namespace modelnet
