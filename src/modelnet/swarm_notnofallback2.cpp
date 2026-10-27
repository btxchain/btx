// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofallback2.h>

namespace modelnet {

SwarmNotNoFallback2Result SwarmNoteNotNoFallback2(const SwarmNotNoFallback2& note, std::string& err)
{
    SwarmNotNoFallback2Result result;
    result.connected = false;
    result.bytes_moved = false;
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.connected = false;
        result.bytes_moved = false;
        err = "PEER";
        return result;
    }
    // A fallback peer is not connected.
    if (note.fallback) {
        result.code = "NOT_CONNECTED";
        result.connected = false;
        result.bytes_moved = false;
        err = "NOT_CONNECTED";
        return result;
    }
    if (note.want_connect) {
        result.code = "HELD";
        result.connected = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.connected = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
