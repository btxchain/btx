// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FLAG13_H
#define BTX_MODELNET_SWARM_FLAG13_H

#include <string>

namespace modelnet {

/**
 * Flagship stage 13 repeat. A second research cycle uses a graduated model
 * as its parent. One training run is not continuous evolution.
 *
 * repeated, produced, and passed stay false on every path.
 */
struct SwarmFlag13 {
    std::string parent_id;
    std::string cycle_id;
    bool parent_graduated{false};
    bool second_cycle{false};
    bool want_repeat{false};
    bool want_pass{false};
};

/**
 * Outcome of a flagship stage 13 repeat note. repeated, produced, and
 * passed stay false on every path. One training run is not continuous
 * evolution.
 */
struct SwarmFlag13Result {
    std::string code;
    bool repeated{false};
    bool produced{false};
    bool passed{false};
};

/**
 * Note a flagship stage 13 repeat. A second research cycle uses a
 * graduated model as its parent. One training run is not continuous
 * evolution.
 * Order, first match wins: an empty parent_id or cycle_id is PARENT.
 * A parent that has not graduated is NOT_GRADUATED. A cycle that is not
 * the second cycle is FIRST_ONLY. want_repeat is NOT_REPEATED. want_pass
 * is UNQUALIFIED. Otherwise the note is NOTED and err is clear.
 * repeated, produced, and passed stay false on every path.
 */
SwarmFlag13Result SwarmStageRepeat(const SwarmFlag13& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FLAG13_H
