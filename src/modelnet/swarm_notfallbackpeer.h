// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFALLBACKPEER_H
#define BTX_MODELNET_SWARM_NOTFALLBACKPEER_H

#include <string>

namespace modelnet {

/**
 * A local note about one peer. want_connect asks this note to connect that
 * peer.
 *
 * A fallback peer is an extra authorized peer outside the chosen set and is
 * not connected by this note.
 * connected stays false on every path.
 */
struct SwarmNotFallbackPeer {
    std::string peer_id;
    bool want_connect{false};
};

/**
 * Outcome of noting a fallback peer. connected stays false on every path:
 * a fallback peer is an extra authorized peer outside the chosen set and is
 * not connected by this note.
 */
struct SwarmNotFallbackPeerResult {
    std::string code;
    bool connected{false};
};

/**
 * Note a fallback peer without connecting it.
 * Order, first match wins: an empty peer_id is PEER.
 * want_connect is NOT_CONNECTED.
 * Otherwise the note is NOTED and err is cleared.
 * connected stays false on every path. A fallback peer is an extra authorized
 * peer outside the chosen set and is not connected by this note.
 */
SwarmNotFallbackPeerResult SwarmNoteNotFallbackPeer(const SwarmNotFallbackPeer& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFALLBACKPEER_H
