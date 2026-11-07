// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofallconn2.h>

#include <string>

namespace modelnet {

SwarmNotNoFallConn2Result SwarmNoteNotNoFallConn2(const SwarmNotNoFallConn2& note, std::string& err)
{
    SwarmNotNoFallConn2Result result;
    result.connected = false;
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.connected = false;
        err = "PEER";
        return result;
    }
    // A fallback peer is not connected.
    if (note.fallback) {
        result.code = "NOT_CONNECTED";
        result.connected = false;
        err = "NOT_CONNECTED";
        return result;
    }
    if (note.want_connect) {
        result.code = "HELD";
        result.connected = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.connected = false;
    err.clear();
    return result;
}

} // namespace modelnet
