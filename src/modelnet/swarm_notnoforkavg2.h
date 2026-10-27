// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFORKAVG2_H
#define BTX_MODELNET_SWARM_NOTNOFORKAVG2_H

#include <string>

namespace modelnet {

/**
 * A local note about one branch. branch_id names the branch.
 * incompatible is whether the branch is incompatible. want_average asks
 * this note to average.
 *
 * Incompatible branches are not averaged. This note averages nothing.
 * averaged stays false on every path.
 */
struct SwarmNotNoForkAvg2 {
    std::string branch_id;
    bool incompatible{false};
    bool want_average{false};
};

/**
 * Outcome of noting a branch. averaged stays false on every path.
 * Incompatible branches are not averaged.
 */
struct SwarmNotNoForkAvg2Result {
    std::string code;
    bool averaged{false};
};

/**
 * Note a branch without averaging it.
 * Order, first match wins: an empty branch_id is BRANCH.
 * incompatible true is NOT_AVERAGED, even when want_average is false.
 * want_average is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * averaged stays false on every path.
 * Incompatible branches are not averaged.
 */
SwarmNotNoForkAvg2Result SwarmNoteNotNoForkAvg2(const SwarmNotNoForkAvg2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFORKAVG2_H
