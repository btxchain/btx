// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fallconn.h>

#include <string>

namespace modelnet {

SwarmFallConnResult SwarmNoteFallConn(const SwarmFallConn& peer, std::string& err)
{
    SwarmFallConnResult result;
    result.connected = false;
    // A fallback peer is not connected.
    if (peer.peer_id.empty()) {
        result.code = "PEER";
        result.connected = false;
        err = "PEER";
        return result;
    }
    if (peer.fallback) {
        result.code = "NOT_CONNECTED";
        result.connected = false;
        err = "NOT_CONNECTED";
        return result;
    }
    if (peer.want_connect) {
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
