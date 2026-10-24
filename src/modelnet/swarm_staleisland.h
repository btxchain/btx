// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_STALEISLAND_H
#define BTX_MODELNET_SWARM_STALEISLAND_H

#include <string>

namespace modelnet {

/**
 * A stale-island record. island_id names the island. stale marks the island
 * stale. want_admit asks this note to admit.
 *
 * A stale island is not admitted. An admit request is held.
 * admitted stays false on every path.
 */
struct SwarmStaleIsland {
    std::string island_id;
    bool stale{false};
    bool want_admit{false};
};

/**
 * Outcome of noting a stale island. admitted stays false on every path.
 */
struct SwarmStaleIslandResult {
    std::string code;
    bool admitted{false};
};

/**
 * Note a stale island. It is not admitted.
 * Order, first match wins: an empty island_id is ISLAND.
 * stale true is NOT_ADMITTED, even when want_admit is false.
 * want_admit true is HELD.
 * Otherwise the code is NOTED and err is cleared.
 * admitted stays false on every path.
 * A stale island is not admitted.
 */
SwarmStaleIslandResult SwarmNoteStaleIsland(const SwarmStaleIsland& island, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_STALEISLAND_H
