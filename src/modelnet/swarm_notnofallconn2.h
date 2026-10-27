// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFALLCONN2_H
#define BTX_MODELNET_SWARM_NOTNOFALLCONN2_H

#include <string>

namespace modelnet {

/**
 * A pure refusal note. A fallback peer is not connected.
 * Nothing broadcasts, spends, launches, mines, or moves bytes.
 */
struct SwarmNotNoFallConn2 {
    std::string peer_id;
    bool fallback{false};
    bool want_connect{false};
};

/**
 * Outcome of noting that a fallback peer is not connected.
 * connected stays false on every path.
 */
struct SwarmNotNoFallConn2Result {
    std::string code;
    bool connected{false};
};

/**
 * Note that a fallback peer is not connected.
 * Order, first match wins: an empty peer_id is PEER. fallback is
 * NOT_CONNECTED even when want_connect is false. want_connect is HELD.
 * Otherwise the note is NOTED and err is clear.
 * connected stays false on every path. Nothing broadcasts, spends,
 * launches, mines, or moves bytes.
 */
SwarmNotNoFallConn2Result SwarmNoteNotNoFallConn2(const SwarmNotNoFallConn2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFALLCONN2_H
