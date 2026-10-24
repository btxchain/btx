// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTEXPLORE_H
#define BTX_MODELNET_SWARM_NOTEXPLORE_H

#include <string>

namespace modelnet {

/**
 * A local note about one slot. want_assign asks this note to assign work
 * from an exploration illustration.
 *
 * An exploration illustration does not assign work. assigned stays false
 * and candidates stays 0 on every path.
 */
struct SwarmNotExplore {
    std::string slot_id;
    bool want_assign{false};
};

/**
 * Outcome of noting an explore request. assigned stays false and
 * candidates stays 0 on every path: an exploration illustration does not
 * assign work.
 */
struct SwarmNotExploreResult {
    std::string code;
    bool assigned{false};
    int candidates{0};
};

/**
 * Note an explore request without assigning work.
 * Order, first match wins: an empty slot_id is SLOT. want_assign is
 * NOT_ASSIGNED. Otherwise the note is NOTED and err is clear.
 * assigned stays false and candidates stays 0 on every path. An exploration
 * illustration does not assign work.
 */
SwarmNotExploreResult SwarmNoteNotExplore(const SwarmNotExplore& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTEXPLORE_H
