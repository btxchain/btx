// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmcp.h>

namespace modelnet {

SwarmNotMcpResult SwarmNoteNotMcp(const SwarmNotMcp& note, std::string& err)
{
    // This note does not open an MCP session.
    if (note.adapter_id.empty()) {
        err = "ADAPTER";
        return SwarmNotMcpResult{"ADAPTER", false, false};
    }
    if (note.want_connect) {
        err = "NOT_CONNECTED";
        return SwarmNotMcpResult{"NOT_CONNECTED", false, false};
    }
    err.clear();
    return SwarmNotMcpResult{"NOTED", false, false};
}

} // namespace modelnet
