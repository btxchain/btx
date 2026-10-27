// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandcur.h>

namespace modelnet {

// A local island cursor records the next step and does not run training.
SwarmIslandCursorResult SwarmAdvanceIslandCursor(const SwarmIslandCursor& cursor, std::string& err)
{
    SwarmIslandCursorResult result;
    result.running = false;
    result.bytes_moved = false;
    if (cursor.island_id.empty()) {
        result.code = "ISLAND";
        err = "ISLAND";
        result.step = 0;
        result.cursor = 0;
        result.running = false;
        result.bytes_moved = false;
        return result;
    }
    if (cursor.recipe_id.empty() || cursor.checkpoint_id.empty()) {
        result.code = "RECIPE";
        err = "RECIPE";
        result.step = cursor.step;
        result.cursor = cursor.cursor;
        result.running = false;
        result.bytes_moved = false;
        return result;
    }
    if (!cursor.grant) {
        result.code = "DATASET";
        err = "DATASET";
        result.step = cursor.step;
        result.cursor = cursor.cursor;
        result.running = false;
        result.bytes_moved = false;
        return result;
    }
    if (cursor.want_run) {
        result.code = "HELD";
        err = "HELD";
        result.step = cursor.step;
        result.cursor = cursor.cursor;
        result.running = false;
        result.bytes_moved = false;
        return result;
    }
    result.code = "NOTED";
    err.clear();
    result.step = cursor.step + 1;
    result.cursor = cursor.cursor + 1;
    result.running = false;
    result.bytes_moved = false;
    return result;
}

} // namespace modelnet
