// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTWALL_H
#define BTX_MODELNET_SWARM_NOTWALL_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note for one node. want_publish asks this note to publish.
 *
 * published and recovered stay false, and seconds stays 0, on every path.
 * This note does not claim a process was killed.
 */
struct SwarmNotWall {
    std::string node_id;
    bool want_publish{false};
};

/**
 * Outcome of noting one node. published and recovered stay false, and
 * seconds stays 0, on every path. This note does not claim a process was
 * killed.
 */
struct SwarmNotWallResult {
    std::string code;
    bool published{false};
    bool recovered{false};
    int64_t seconds{0};
};

/**
 * Note a node without publishing.
 * Order, first match wins: an empty node_id is NODE. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published and recovered stay false, and seconds stays 0, on every path.
 * This note does not claim a process was killed.
 */
SwarmNotWallResult SwarmNoteNotWall(const SwarmNotWall& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTWALL_H
