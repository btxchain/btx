// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOAVGFORK_H
#define BTX_MODELNET_SWARM_NOTNOAVGFORK_H

#include <string>

namespace modelnet {

/**
 * A local note about one branch. compatible is false when the branch cannot
 * be joined. want_average asks this note to average that branch.
 *
 * An incompatible branch is not averaged. averaged and forked stay false
 * on every path. This note does not fork a tree and does not move weights.
 */
struct SwarmNotNoAvgFork {
    std::string branch_id;
    bool compatible{false};
    bool want_average{false};
};

/**
 * Outcome of noting a branch. averaged and forked stay false on every path.
 * An incompatible branch is not averaged. This note does not fork a tree
 * and does not move weights.
 */
struct SwarmNotNoAvgForkResult {
    std::string code;
    bool averaged{false};
    bool forked{false};
};

/**
 * Note a branch without averaging it and without forking a tree.
 * Order, first match wins: an empty branch_id is BRANCH. compatible false
 * is FORK even when want_average is false. want_average is FORK. Otherwise
 * the note is NOTED and err is clear.
 * averaged and forked stay false on every path. An incompatible branch is
 * not averaged. This note does not fork a tree and does not move weights.
 */
SwarmNotNoAvgForkResult SwarmNoteNotNoAvgFork(const SwarmNotNoAvgFork& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOAVGFORK_H
