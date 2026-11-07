// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNO90S_H
#define BTX_MODELNET_SWARM_NOTNO90S_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about block spacing. spacing_id names the spacing. seconds
 * is the spacing in seconds. want_guarantee asks this note to treat the
 * spacing as a wall-clock guarantee.
 *
 * A 90-second block spacing is not a wall-clock guarantee. guaranteed
 * stays false, and applied_seconds stays 0, on every path.
 */
struct SwarmNotNo90s {
    std::string spacing_id;
    int64_t seconds{0};
    bool want_guarantee{false};
};

/**
 * Outcome of noting block spacing. guaranteed stays false, and
 * applied_seconds stays 0, on every path. A 90-second block spacing is
 * not a wall-clock guarantee.
 */
struct SwarmNotNo90sResult {
    std::string code;
    bool guaranteed{false};
    int64_t applied_seconds{0};
};

/**
 * Note block spacing without treating it as a wall-clock guarantee.
 * Order, first match wins: an empty spacing_id is SPACING. A seconds
 * value that is not exactly 90 is NOT_GUARANTEE, even when want_guarantee
 * is false. want_guarantee is NOT_GUARANTEE. Otherwise the note is NOTED
 * and err is clear. A 90-second block spacing is not a wall-clock
 * guarantee. guaranteed stays false, and applied_seconds stays 0, on
 * every path.
 */
SwarmNotNo90sResult SwarmNoteNotNo90s(const SwarmNotNo90s& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNO90S_H
