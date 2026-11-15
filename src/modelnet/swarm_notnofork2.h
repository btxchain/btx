// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFORK2_H
#define BTX_MODELNET_SWARM_NOTNOFORK2_H

#include <string>

namespace modelnet {

/**
 * A local note about one branch. branch_id names the branch.
 * incompatible is whether the branch is incompatible. want_average asks
 * this note to average.
 *
 * Incompatible branches fork instead of being averaged. averaged stays
 * false and bytes_moved stays false on every path.
 */
struct SwarmNotNoFork2 {
    std::string branch_id;
    bool incompatible{false};
    bool want_average{false};
};

/**
 * Outcome of noting a branch. averaged stays false and bytes_moved stays
 * false on every path. Incompatible branches fork instead of being
 * averaged.
 */
struct SwarmNotNoFork2Result {
    std::string code;
    bool averaged{false};
    bool bytes_moved{false};
};

/**
 * Note a branch without averaging it or moving bytes.
 * Order, first match wins: an empty branch_id is BRANCH.
 * incompatible true is FORKED, even when want_average is false.
 * want_average is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * averaged stays false and bytes_moved stays false on every path.
 * Incompatible branches fork instead of being averaged.
 */
SwarmNotNoFork2Result SwarmNoteNotNoFork2(const SwarmNotNoFork2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFORK2_H
