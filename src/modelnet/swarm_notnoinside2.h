// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOINSIDE2_H
#define BTX_MODELNET_SWARM_NOTNOINSIDE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_exec asks this note to run work
 * outside the process. node_id names the node.
 *
 * The swarm control plane stays inside btxd. launched stays false on
 * every path.
 */
struct SwarmNotNoInside2 {
    std::string node_id;
    bool want_exec{false};
};

/**
 * Outcome of noting a node. launched stays false on every path: the
 * swarm control plane stays inside btxd.
 */
struct SwarmNotNoInside2Result {
    std::string code;
    bool launched{false};
};

/**
 * Note a node while the swarm control plane stays inside btxd.
 * Order, first match wins: an empty node_id is NODE.
 * want_exec is HELD. Otherwise the note is NOTED and err is cleared.
 * launched stays false on every path.
 */
SwarmNotNoInside2Result SwarmNoteNotNoInside2(const SwarmNotNoInside2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOINSIDE2_H
