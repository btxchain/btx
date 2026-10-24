// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FALLCONN_H
#define BTX_MODELNET_SWARM_FALLCONN_H

#include <string>

namespace modelnet {

/**
 * A fallback-peer record. peer_id names the peer. fallback marks a
 * fallback peer. want_connect asks this record to connect.
 *
 * A fallback peer is not connected. A connect request is held.
 * connected stays false on every path. No hostname, IP, or key path
 * is used.
 */
struct SwarmFallConn {
    std::string peer_id;
    bool fallback{false};
    bool want_connect{false};
};

/**
 * Outcome of noting a fallback peer. connected stays false on every
 * path. A fallback peer is not connected.
 */
struct SwarmFallConnResult {
    std::string code;
    bool connected{false};
};

/**
 * Note a fallback peer without connecting it.
 * Order, first match wins: an empty peer_id is PEER. fallback true is
 * NOT_CONNECTED, even when want_connect is false. want_connect true is
 * HELD. Otherwise the note is NOTED and err is clear.
 * connected stays false on every path. A fallback peer is not connected.
 */
SwarmFallConnResult SwarmNoteFallConn(const SwarmFallConn& peer, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FALLCONN_H
