// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOWAN_H
#define BTX_MODELNET_SWARM_NOTNOWAN_H

#include <string>

namespace modelnet {

/**
 * A local note about an island. island_id names the island.
 * want_exchange asks this note to exchange a WAN update.
 *
 * An island note exchanges no WAN update. exchanged stays false and
 * bytes_moved stays false on every path.
 */
struct SwarmNotNoWan {
    std::string island_id;
    bool want_exchange{false};
};

/**
 * Outcome of noting an island. exchanged stays false and bytes_moved
 * stays false on every path: an island note exchanges no WAN update.
 */
struct SwarmNotNoWanResult {
    std::string code;
    bool exchanged{false};
    bool bytes_moved{false};
};

/**
 * Note an island without exchanging a WAN update.
 * Order, first match wins: an empty island_id is ISLAND.
 * want_exchange is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * exchanged stays false and bytes_moved stays false on every path.
 * An island note exchanges no WAN update.
 */
SwarmNotNoWanResult SwarmNoteNotNoWan(const SwarmNotNoWan& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOWAN_H
