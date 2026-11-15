// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMCP_H
#define BTX_MODELNET_SWARM_NOTNOMCP_H

#include <string>

namespace modelnet {

struct SwarmNotNoMcp {
    std::string tool_id;
    bool want_call{false};
};

struct SwarmNotNoMcpResult {
    std::string code;
    bool called{false};
    bool bytes_moved{false};
};

/** Record a note only. This note makes no outbound tool call. */
SwarmNotNoMcpResult SwarmNoteNotNoMcp(const SwarmNotNoMcp& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMCP_H
