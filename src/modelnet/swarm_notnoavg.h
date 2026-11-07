// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOAVG_H
#define BTX_MODELNET_SWARM_NOTNOAVG_H

#include <string>

namespace modelnet {

/**
 * A local note about one branch. compatible is false when the branch cannot
 * be joined. want_average asks this note to average that branch.
 *
 * An incompatible branch is not averaged. averaged and bytes_moved stay
 * false on every path. This note does not move bytes.
 */
struct SwarmNotNoAvg {
    std::string branch_id;
    bool compatible{false};
    bool want_average{false};
};

/**
 * Outcome of noting a branch. averaged and bytes_moved stay false on every
 * path. An incompatible branch is not averaged. This note does not move
 * bytes.
 */
struct SwarmNotNoAvgResult {
    std::string code;
    bool averaged{false};
    bool bytes_moved{false};
};

/**
 * Note a branch without averaging it and without moving bytes.
 * Order, first match wins: an empty branch_id is BRANCH. compatible false
 * is SEPARATE even when want_average is false. want_average is HELD.
 * Otherwise the note is NOTED and err is clear.
 * averaged and bytes_moved stay false on every path. An incompatible branch
 * is not averaged.
 */
SwarmNotNoAvgResult SwarmNoteNotNoAvg(const SwarmNotNoAvg& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOAVG_H
