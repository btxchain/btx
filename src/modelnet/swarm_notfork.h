// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFORK_H
#define BTX_MODELNET_SWARM_NOTFORK_H

#include <string>

namespace modelnet {

/**
 * A local note about one branch. compatible is false when the branch cannot
 * be joined. want_average asks this note to average that branch.
 *
 * Incompatible branches fork instead of being averaged. averaged and
 * bytes_moved stay false on every path.
 */
struct SwarmNotFork {
    std::string branch_id;
    bool compatible{false};
    bool want_average{false};
};

/**
 * Outcome of noting a branch. averaged and bytes_moved stay false on every
 * path: incompatible branches fork instead of being averaged.
 */
struct SwarmNotForkResult {
    std::string code;
    bool averaged{false};
    bool bytes_moved{false};
};

/**
 * Note a branch without averaging it.
 * Order, first match wins: an empty branch_id is BRANCH. compatible false
 * is FORK even when want_average is false. want_average is FORK. Otherwise
 * the note is NOTED and err is clear.
 * averaged and bytes_moved stay false on every path.
 */
SwarmNotForkResult SwarmNoteNotFork(const SwarmNotFork& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFORK_H
