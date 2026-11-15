// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTTWONODE_H
#define BTX_MODELNET_SWARM_NOTTWONODE_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_pair asks this note to pair two machines
 * for collaborative training.
 *
 * Two-machine collaborative training is out of scope for this note.
 * paired stays false on every path.
 */
struct SwarmNotTwoNode {
    std::string node_id;
    bool want_pair{false};
};

/**
 * Outcome of noting a two-node request. paired stays false on every path:
 * two-machine collaborative training is out of scope for this note.
 */
struct SwarmNotTwoNodeResult {
    std::string code;
    bool paired{false};
};

/**
 * Note a two-node request without pairing machines for collaborative training.
 * Order, first match wins: an empty node_id is NODE.
 * want_pair is OUT_OF_SCOPE.
 * Otherwise the note is NOTED and err is clear.
 * paired stays false on every path.
 */
SwarmNotTwoNodeResult SwarmNoteNotTwoNode(const SwarmNotTwoNode& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTTWONODE_H
