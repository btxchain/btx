// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNO90BLK2_H
#define BTX_MODELNET_SWARM_NOTNO90BLK2_H

#include <string>

namespace modelnet {

/**
 * A local note about block spacing. clock_id names the clock.
 * want_guarantee asks this note to treat the spacing as a wall-clock
 * guarantee.
 *
 * A 90-second block spacing is not a wall-clock guarantee. guaranteed
 * stays false on every path.
 */
struct SwarmNotNo90Blk2 {
    std::string clock_id;
    bool want_guarantee{false};
};

/**
 * Outcome of noting block spacing. guaranteed stays false on every path.
 * A 90-second block spacing is not a wall-clock guarantee.
 */
struct SwarmNotNo90Blk2Result {
    std::string code;
    bool guaranteed{false};
};

/**
 * Note block spacing without treating it as a wall-clock guarantee.
 * Order, first match wins: an empty clock_id is CLOCK. want_guarantee
 * is HELD. Otherwise the note is NOTED and err is cleared. A 90-second
 * block spacing is not a wall-clock guarantee. guaranteed stays false
 * on every path.
 */
SwarmNotNo90Blk2Result SwarmNoteNotNo90Blk2(const SwarmNotNo90Blk2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNO90BLK2_H
