// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nota2a.h>

#include <string>

namespace modelnet {

SwarmNotA2aResult SwarmNoteNotA2a(const SwarmNotA2a& note, std::string& err)
{
    SwarmNotA2aResult result;
    result.connected = false;
    result.launched = false;
    // This note does not open an agent-to-agent session.
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.connected = false;
        result.launched = false;
        err = "PEER";
        return result;
    }
    if (note.want_connect) {
        result.code = "NOT_CONNECTED";
        result.connected = false;
        result.launched = false;
        err = "NOT_CONNECTED";
        return result;
    }
    result.code = "NOTED";
    result.connected = false;
    result.launched = false;
    err.clear();
    return result;
}

} // namespace modelnet
