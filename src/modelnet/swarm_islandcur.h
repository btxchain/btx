// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ISLANDCUR_H
#define BTX_MODELNET_SWARM_ISLANDCUR_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmIslandCursor {
    std::string island_id;
    std::string recipe_id;
    std::string checkpoint_id;
    int64_t step{0};
    int64_t cursor{0};
    bool grant{false};
    bool want_run{false};
};

struct SwarmIslandCursorResult {
    std::string code;
    bool running{false};
    bool bytes_moved{false};
    int64_t step{0};
    int64_t cursor{0};
};

/**
 * A local island cursor records the next step and does not run training.
 * An empty island_id is ISLAND. An empty recipe_id or checkpoint_id is
 * RECIPE, including when grant is true. A missing grant is DATASET. A
 * request that wants a run is HELD. Otherwise the note is NOTED and the
 * recorded step and cursor each advance by one. running and bytes_moved
 * stay false on every path.
 */
SwarmIslandCursorResult SwarmAdvanceIslandCursor(const SwarmIslandCursor& cursor, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ISLANDCUR_H
