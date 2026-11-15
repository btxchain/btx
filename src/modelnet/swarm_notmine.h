// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMINE_H
#define BTX_MODELNET_SWARM_NOTMINE_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_mine asks this note to mine.
 *
 * This note does not mine past the ExactReplay stall. mined stays
 * false on every path.
 */
struct SwarmNotMine {
    std::string node_id;
    bool want_mine{false};
};

/**
 * Outcome of noting a node. mined stays false on every path.
 */
struct SwarmNotMineResult {
    std::string code;
    bool mined{false};
};

/**
 * Note a node without mining past the ExactReplay stall.
 * Order, first match wins: an empty node_id is MINE.
 * want_mine is NOT_MINED. Otherwise the note is NOTED and err is clear.
 * mined stays false on every path. This note does not mine.
 */
SwarmNotMineResult SwarmNoteNotMine(const SwarmNotMine& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMINE_H
