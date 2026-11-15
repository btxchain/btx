// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTWEEK_H
#define BTX_MODELNET_SWARM_NOTWEEK_H

#include <string>

namespace modelnet {

/**
 * A local note about one window counted in blocks. window_id names the
 * window. blocks is the block count. want_guarantee asks this note to
 * treat the count as a wall-clock guarantee.
 *
 * 6720 blocks is not a wall-clock week. guaranteed stays false, and
 * seconds stays 0, on every path.
 */
struct SwarmNotWeek {
    std::string window_id;
    int blocks{0};
    bool want_guarantee{false};
};

/**
 * Outcome of noting a block window. guaranteed stays false, and seconds
 * stays 0, on every path. 6720 blocks is not a wall-clock week.
 */
struct SwarmNotWeekResult {
    std::string code;
    bool guaranteed{false};
    int seconds{0};
};

/**
 * Note a block window without treating it as a wall-clock week.
 * Order, first match wins: an empty window_id is WINDOW. A block count
 * that is not exactly 6720 is NOT_GUARANTEE, even when want_guarantee is
 * false. want_guarantee is NOT_GUARANTEE. Otherwise the note is NOTED and
 * err is clear. 6720 blocks is not a wall-clock week. guaranteed stays
 * false, and seconds stays 0, on every path.
 */
SwarmNotWeekResult SwarmNoteNotWeek(const SwarmNotWeek& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTWEEK_H
