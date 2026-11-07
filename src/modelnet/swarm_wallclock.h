// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_WALLCLOCK_H
#define BTX_MODELNET_SWARM_WALLCLOCK_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note of block spacing as elapsed time. channel_id names the
 * channel. blocks is the noted block count. Spacing is 90 seconds per
 * block, so 160 blocks is 14400 seconds. want_guarantee asks this note
 * to treat that spacing as a wall-clock guarantee.
 *
 * A target interval is not a wall-clock guarantee. wall_clock_guaranteed
 * stays false on every path. Nothing is mined and nothing is broadcast.
 * No hostnames or IPs are used.
 */
struct SwarmWallClock {
    std::string channel_id;
    int64_t blocks{0};
    bool want_guarantee{false};
};

/**
 * Outcome of noting block spacing. elapsed_seconds is blocks times 90
 * when that product fits, and 0 otherwise. wall_clock_guaranteed stays
 * false: nothing is mined and nothing is broadcast.
 */
struct SwarmWallClockResult {
    int64_t elapsed_seconds{0};
    bool wall_clock_guaranteed{false};
    std::string code;
};

/**
 * Note block spacing without mining or broadcasting.
 * Order, first match wins: an empty channel_id or blocks below 0 is
 * ELAPSED, with elapsed_seconds 0. A block count above INT64_MAX / 90
 * is ELAPSED, with elapsed_seconds 0, so the multiply cannot overflow.
 * want_guarantee is NOT_GUARANTEED for any blocks at or above 0 whose
 * product fits, including 160. A target interval is not a wall-clock
 * guarantee. Otherwise the note is NOTED and err is cleared.
 * elapsed_seconds is blocks * 90 on NOT_GUARANTEED and NOTED.
 * wall_clock_guaranteed stays false on every path. Nothing is mined
 * and nothing is broadcast.
 */
SwarmWallClockResult SwarmNoteWallClock(const SwarmWallClock& clock, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_WALLCLOCK_H
