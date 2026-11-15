// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOISLAND2_H
#define BTX_MODELNET_SWARM_NOTNOISLAND2_H

#include <string>

namespace modelnet {

/**
 * A local note about one island admission. want_exchange asks this note to
 * exchange a WAN update for that island.
 *
 * Island admission exchanges no WAN update. exchanged and bytes_moved stay
 * false on every path.
 */
struct SwarmNotNoIsland2 {
    std::string island_id;
    bool want_exchange{false};
};

/**
 * Outcome of noting an island admission. exchanged and bytes_moved stay
 * false on every path: island admission exchanges no WAN update.
 */
struct SwarmNotNoIsland2Result {
    std::string code;
    bool exchanged{false};
    bool bytes_moved{false};
};

/**
 * Note an island admission without exchanging a WAN update. Order, first
 * match wins: an empty island_id is ISLAND. want_exchange is HELD.
 * Otherwise the note is NOTED and err is clear. exchanged and bytes_moved
 * stay false on every path. Island admission exchanges no WAN update.
 */
SwarmNotNoIsland2Result SwarmNoteNotNoIsland2(const SwarmNotNoIsland2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOISLAND2_H
