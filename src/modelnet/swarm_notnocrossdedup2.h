// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCROSSDEDUP2_H
#define BTX_MODELNET_SWARM_NOTNOCROSSDEDUP2_H

#include <string>

namespace modelnet {

/**
 * A local note that a realm might move bytes via cross-realm dedup.
 * want_move asks this note to move them.
 *
 * Cross-realm dedup moves no bytes. moved and bytes_moved stay false on
 * every path.
 */
struct SwarmNotNoCrossDedup2 {
    std::string realm_id;
    bool want_move{false};
};

/**
 * Outcome of noting a cross-realm dedup request. moved and bytes_moved stay
 * false on every path: cross-realm dedup moves no bytes.
 */
struct SwarmNotNoCrossDedup2Result {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note that cross-realm dedup moves no bytes.
 * Order, first match wins: an empty realm_id is REALM. want_move is HELD.
 * Otherwise the note is NOTED and err is clear.
 * moved and bytes_moved stay false on every path.
 */
SwarmNotNoCrossDedup2Result SwarmNoteNotNoCrossDedup2(const SwarmNotNoCrossDedup2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCROSSDEDUP2_H
