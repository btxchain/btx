// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSTALL_H
#define BTX_MODELNET_SWARM_NOTSTALL_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_mine asks this note to mine.
 *
 * Mining does not pass the ExactReplay stall. mined and passed_stall stay
 * false on every path.
 */
struct SwarmNotStall {
    std::string node_id;
    bool want_mine{false};
};

/**
 * Outcome of noting a node. mined and passed_stall stay false on every path.
 * Mining does not pass the ExactReplay stall.
 */
struct SwarmNotStallResult {
    std::string code;
    bool mined{false};
    bool passed_stall{false};
};

/**
 * Note a node without mining past the ExactReplay stall.
 * Order, first match wins: an empty node_id is NODE.
 * want_mine is NOT_MINED. Otherwise the note is NOTED and err is clear.
 * mined and passed_stall stay false on every path. Mining does not pass
 * the ExactReplay stall.
 */
SwarmNotStallResult SwarmNoteNotStall(const SwarmNotStall& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSTALL_H
