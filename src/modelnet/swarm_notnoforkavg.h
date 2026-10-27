// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFORKAVG_H
#define BTX_MODELNET_SWARM_NOTNOFORKAVG_H

#include <string>

namespace modelnet {

/**
 * A local note about one branch. branch_id names the branch.
 * incompatible is whether the branch is incompatible. want_average asks
 * this note to average.
 *
 * An incompatible branch forks instead of being averaged, and this note
 * averages nothing. averaged stays false and bytes_moved stays false on
 * every path.
 */
struct SwarmNotNoForkAvg {
    std::string branch_id;
    bool incompatible{false};
    bool want_average{false};
};

/**
 * Outcome of noting a branch. averaged stays false and bytes_moved stays
 * false on every path. An incompatible branch forks instead of being
 * averaged, and this note averages nothing.
 */
struct SwarmNotNoForkAvgResult {
    std::string code;
    bool averaged{false};
    bool bytes_moved{false};
};

/**
 * Note a branch without averaging it or moving bytes.
 * Order, first match wins: an empty branch_id is BRANCH.
 * incompatible true is FORK, even when want_average is false.
 * want_average is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * averaged stays false and bytes_moved stays false on every path.
 * An incompatible branch forks instead of being averaged, and this note
 * averages nothing.
 */
SwarmNotNoForkAvgResult SwarmNoteNotNoForkAvg(const SwarmNotNoForkAvg& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFORKAVG_H
