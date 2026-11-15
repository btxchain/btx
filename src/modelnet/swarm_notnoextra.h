// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEXTRA_H
#define BTX_MODELNET_SWARM_NOTNOEXTRA_H

#include <string>

namespace modelnet {

/**
 * A local note about one peer. fallback marks a fallback peer outside the
 * chosen set. want_connect asks this note to connect that peer.
 *
 * A fallback peer outside the chosen set is not connected.
 * connected and bytes_moved stay false on every path.
 */
struct SwarmNotNoExtra {
    std::string peer_id;
    bool fallback{false};
    bool want_connect{false};
};

/**
 * Outcome of noting a peer. connected and bytes_moved stay false
 * on every path.
 */
struct SwarmNotNoExtraResult {
    std::string code;
    bool connected{false};
    bool bytes_moved{false};
};

/**
 * Note a peer without connecting it.
 * Order, first match wins: an empty peer_id is PEER. fallback is
 * NOT_CONNECTED even when want_connect is false. want_connect is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * connected and bytes_moved stay false on every path. A fallback peer
 * outside the chosen set is not connected.
 */
SwarmNotNoExtraResult SwarmNoteNotNoExtra(const SwarmNotNoExtra& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEXTRA_H
