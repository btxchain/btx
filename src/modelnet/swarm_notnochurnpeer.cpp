// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnochurnpeer.h>

#include <string>

namespace modelnet {

SwarmNotNoChurnPeerResult SwarmNoteNotNoChurnPeer(const SwarmNotNoChurnPeer& note, std::string& err)
{
    SwarmNotNoChurnPeerResult result;
    result.sent = false;
    result.bytes_moved = false;
    // A churned peer sends nothing and moves no bytes.
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.sent = false;
        result.bytes_moved = false;
        err = "PEER";
        return result;
    }
    if (note.churned) {
        result.code = "NOT_CONNECTED";
        result.sent = false;
        result.bytes_moved = false;
        err = "NOT_CONNECTED";
        return result;
    }
    if (note.want_send) {
        result.code = "HELD";
        result.sent = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.sent = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
