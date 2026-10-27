// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMCP_H
#define BTX_MODELNET_SWARM_NOTMCP_H

#include <string>

namespace modelnet {

struct SwarmNotMcp {
    std::string adapter_id;
    bool want_connect{false};
};

struct SwarmNotMcpResult {
    std::string code;
    bool connected{false};
    bool launched{false};
};

/** Record a note only. This note does not open an MCP session. */
SwarmNotMcpResult SwarmNoteNotMcp(const SwarmNotMcp& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMCP_H
