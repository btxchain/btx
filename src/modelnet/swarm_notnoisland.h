// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOISLAND_H
#define BTX_MODELNET_SWARM_NOTNOISLAND_H

#include <string>

namespace modelnet {

/**
 * A local note about one island. want_average asks this note to average
 * weights for that island.
 *
 * A stale island exchanges no weights. averaged and bytes_moved stay false
 * on every path.
 */
struct SwarmNotNoIsland {
    std::string island_id;
    bool stale{false};
    bool want_average{false};
};

/**
 * Outcome of noting an island. averaged and bytes_moved stay false on
 * every path: a stale island exchanges no weights.
 */
struct SwarmNotNoIslandResult {
    std::string code;
    bool averaged{false};
    bool bytes_moved{false};
};

/**
 * Note an island without exchanging weights. Order, first match wins: an
 * empty island_id is ISLAND. stale is STALE even when want_average is false.
 * want_average is HELD. Otherwise the note is NOTED and err is clear.
 * averaged and bytes_moved stay false on every path. A stale island
 * exchanges no weights.
 */
SwarmNotNoIslandResult SwarmNoteNotNoIsland(const SwarmNotNoIsland& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOISLAND_H
