// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofail.h>

#include <string>

namespace modelnet {

SwarmNotNoFailResult SwarmNoteNotNoFail(const SwarmNotNoFail& note, std::string& err)
{
    // A failover note opens no connection and moves no bytes.
    SwarmNotNoFailResult result;
    result.connected = false;
    result.bytes_moved = false;
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.connected = false;
        result.bytes_moved = false;
        err = "PEER";
        return result;
    }
    if (note.want_connect) {
        result.code = "NOT_CONNECTED";
        result.connected = false;
        result.bytes_moved = false;
        err = "NOT_CONNECTED";
        return result;
    }
    result.code = "NOTED";
    result.connected = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
