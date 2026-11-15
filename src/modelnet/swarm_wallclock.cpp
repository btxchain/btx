// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wallclock.h>

#include <cstdint>

namespace modelnet {

static constexpr int64_t kSecondsPerBlock = 90;

SwarmWallClockResult SwarmNoteWallClock(const SwarmWallClock& clock, std::string& err)
{
    SwarmWallClockResult result;
    result.elapsed_seconds = 0;
    result.wall_clock_guaranteed = false;
    if (clock.channel_id.empty() || clock.blocks < 0) {
        result.elapsed_seconds = 0;
        result.wall_clock_guaranteed = false;
        result.code = "ELAPSED";
        err = "ELAPSED";
        return result;
    }
    // Spacing is 90 seconds per block. A product that does not fit in
    // int64_t is not an elapsed time. Nothing is mined and nothing is
    // broadcast.
    if (clock.blocks > INT64_MAX / kSecondsPerBlock) {
        result.elapsed_seconds = 0;
        result.wall_clock_guaranteed = false;
        result.code = "ELAPSED";
        err = "ELAPSED";
        return result;
    }
    const int64_t elapsed = clock.blocks * kSecondsPerBlock;
    // A target interval is not a wall-clock guarantee. This wins for
    // any blocks >= 0 whose product fits, including 160.
    if (clock.want_guarantee) {
        result.elapsed_seconds = elapsed;
        result.wall_clock_guaranteed = false;
        result.code = "NOT_GUARANTEED";
        err = "NOT_GUARANTEED";
        return result;
    }
    result.elapsed_seconds = elapsed;
    result.wall_clock_guaranteed = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
