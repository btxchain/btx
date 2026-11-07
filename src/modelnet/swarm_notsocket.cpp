// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsocket.h>

#include <string>

namespace modelnet {

SwarmNotSocketResult SwarmNoteNotSocket(const SwarmNotSocket& note, std::string& err)
{
    SwarmNotSocketResult result;
    result.connected = false;
    result.socket_opened = false;
    // Family discovery stays a local catalog and opens no socket.
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.connected = false;
        result.socket_opened = false;
        err = "PEER";
        return result;
    }
    if (note.want_connect) {
        result.code = "NO_SOCKET";
        result.connected = false;
        result.socket_opened = false;
        err = "NO_SOCKET";
        return result;
    }
    result.code = "NOTED";
    result.connected = false;
    result.socket_opened = false;
    err.clear();
    return result;
}

} // namespace modelnet
