// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSPACING_H
#define BTX_MODELNET_SWARM_NOTSPACING_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about block spacing for one height. height_id names the
 * height. want_wall_clock asks this note to treat spacing as a wall-clock
 * guarantee.
 *
 * A 90-second block spacing is not a wall-clock guarantee. guaranteed
 * stays false, and seconds stays 0, on every path.
 */
struct SwarmNotSpacing {
    std::string height_id;
    bool want_wall_clock{false};
};

/**
 * Outcome of noting block spacing. guaranteed stays false, and seconds
 * stays 0, on every path. A 90-second block spacing is not a wall-clock
 * guarantee.
 */
struct SwarmNotSpacingResult {
    std::string code;
    bool guaranteed{false};
    int64_t seconds{0};
};

/**
 * Note block spacing without treating it as a wall-clock guarantee.
 * Order, first match wins: an empty height_id is HEIGHT. want_wall_clock
 * is NOT_GUARANTEE. Otherwise the note is NOTED and err is clear.
 * A 90-second block spacing is not a wall-clock guarantee. guaranteed
 * stays false, and seconds stays 0, on every path.
 */
SwarmNotSpacingResult SwarmNoteNotSpacing(const SwarmNotSpacing& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSPACING_H
