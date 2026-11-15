// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNO160S_H
#define BTX_MODELNET_SWARM_NOTNO160S_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about a clock counted in blocks. clock_id names the clock.
 * blocks is the block count. want_wallclock asks this note to treat the
 * count as a wall-clock guarantee.
 *
 * One hundred sixty blocks is not 14400 seconds of wall clock. guaranteed
 * stays false, and applied_seconds stays 0, on every path.
 */
struct SwarmNotNo160s {
    std::string clock_id;
    int64_t blocks{0};
    bool want_wallclock{false};
};

/**
 * Outcome of noting a block clock. guaranteed stays false, and
 * applied_seconds stays 0, on every path. One hundred sixty blocks is
 * not 14400 seconds of wall clock.
 */
struct SwarmNotNo160sResult {
    std::string code;
    bool guaranteed{false};
    int64_t applied_seconds{0};
};

/**
 * Note a block clock without treating it as 14400 seconds of wall clock.
 * Order, first match wins: an empty clock_id is CLOCK. A blocks value
 * that is not exactly 160 is NOT_GUARANTEE, even when want_wallclock is
 * false. want_wallclock is NOT_GUARANTEE. Otherwise the note is NOTED and
 * err is clear. One hundred sixty blocks is not 14400 seconds of wall
 * clock. guaranteed stays false, and applied_seconds stays 0, on every
 * path.
 */
SwarmNotNo160sResult SwarmNoteNotNo160s(const SwarmNotNo160s& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNO160S_H
