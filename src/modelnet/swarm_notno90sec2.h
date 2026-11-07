// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNO90SEC2_H
#define BTX_MODELNET_SWARM_NOTNO90SEC2_H

#include <string>

namespace modelnet {

/**
 * A local note about block spacing. block_id names the block.
 * wall_clock asks this note to treat the spacing as a wall-clock
 * measurement. want_guarantee asks this note to treat the spacing as a
 * wall-clock guarantee.
 *
 * A 90-second block spacing is not a wall-clock guarantee. guaranteed
 * stays false on every path.
 */
struct SwarmNotNo90Sec2 {
    std::string block_id;
    bool wall_clock{false};
    bool want_guarantee{false};
};

/**
 * Outcome of noting block spacing. guaranteed stays false on every path.
 * A 90-second block spacing is not a wall-clock guarantee.
 */
struct SwarmNotNo90Sec2Result {
    std::string code;
    bool guaranteed{false};
};

/**
 * Note block spacing without treating it as a wall-clock guarantee.
 * Order, first match wins: an empty block_id is BLOCK. wall_clock is
 * NOT_GUARANTEED, even when want_guarantee is false. want_guarantee is
 * HELD. Otherwise the note is NOTED and err is cleared. A 90-second
 * block spacing is not a wall-clock guarantee. guaranteed stays false
 * on every path.
 */
SwarmNotNo90Sec2Result SwarmNoteNotNo90Sec2(const SwarmNotNo90Sec2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNO90SEC2_H
