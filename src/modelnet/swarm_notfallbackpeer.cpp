// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfallbackpeer.h>

#include <string>

namespace modelnet {

SwarmNotFallbackPeerResult SwarmNoteNotFallbackPeer(const SwarmNotFallbackPeer& note, std::string& err)
{
    SwarmNotFallbackPeerResult result;
    result.connected = false;
    // A fallback peer is an extra authorized peer outside the chosen set and
    // is not connected by this note.
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.connected = false;
        err = "PEER";
        return result;
    }
    if (note.want_connect) {
        result.code = "NOT_CONNECTED";
        result.connected = false;
        err = "NOT_CONNECTED";
        return result;
    }
    result.code = "NOTED";
    result.connected = false;
    err.clear();
    return result;
}

} // namespace modelnet
