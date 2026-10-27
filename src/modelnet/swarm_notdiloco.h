// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTDILOCO_H
#define BTX_MODELNET_SWARM_NOTDILOCO_H

#include <string>

namespace modelnet {

/**
 * A local note about one island. want_average asks this note to average
 * weights across islands.
 *
 * Island admission does not exchange WAN updates or average weights.
 * averaged stays false on every path. bytes_moved stays false on every path.
 */
struct SwarmNotDiloco {
    std::string island_id;
    bool want_average{false};
};

/**
 * Outcome of noting an island average request. averaged stays false and
 * bytes_moved stays false on every path: island admission does not exchange
 * WAN updates or average weights.
 */
struct SwarmNotDilocoResult {
    std::string code;
    bool averaged{false};
    bool bytes_moved{false};
};

/**
 * Note an island average request without exchanging WAN updates or averaging
 * weights. Order, first match wins: an empty island_id is ISLAND.
 * want_average is NOT_AVERAGED.
 * Otherwise the note is NOTED and err is clear.
 * averaged stays false and bytes_moved stays false on every path.
 */
SwarmNotDilocoResult SwarmNoteNotDiloco(const SwarmNotDiloco& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTDILOCO_H
