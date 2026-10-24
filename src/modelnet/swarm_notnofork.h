// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFORK_H
#define BTX_MODELNET_SWARM_NOTNOFORK_H

#include <string>

namespace modelnet {

/**
 * A local note about one branch. branch_id names the branch.
 * compatible is whether the branch is compatible. want_merge asks this
 * note to merge.
 *
 * Incompatible branches fork instead of being merged, and this note
 * merges nothing. merged stays false and bytes_moved stays false on
 * every path.
 */
struct SwarmNotNoFork {
    std::string branch_id;
    bool compatible{false};
    bool want_merge{false};
};

/**
 * Outcome of noting a branch. merged stays false and bytes_moved stays
 * false on every path. Incompatible branches fork instead of being
 * merged, and this note merges nothing.
 */
struct SwarmNotNoForkResult {
    std::string code;
    bool merged{false};
    bool bytes_moved{false};
};

/**
 * Note a branch without merging it or moving bytes.
 * Order, first match wins: an empty branch_id is BRANCH.
 * compatible false is FORK, even when want_merge is false.
 * want_merge is FORK.
 * Otherwise the note is NOTED and err is cleared.
 * merged stays false and bytes_moved stays false on every path.
 * Incompatible branches fork instead of being merged, and this note
 * merges nothing.
 */
SwarmNotNoForkResult SwarmNoteNotNoFork(const SwarmNotNoFork& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFORK_H
