// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoisland.h>

#include <string>

namespace modelnet {

SwarmNotNoIslandResult SwarmNoteNotNoIsland(const SwarmNotNoIsland& note, std::string& err)
{
    SwarmNotNoIslandResult result;
    result.averaged = false;
    result.bytes_moved = false;
    // A stale island exchanges no weights.
    if (note.island_id.empty()) {
        result.code = "ISLAND";
        result.averaged = false;
        result.bytes_moved = false;
        err = "ISLAND";
        return result;
    }
    if (note.stale) {
        result.code = "STALE";
        result.averaged = false;
        result.bytes_moved = false;
        err = "STALE";
        return result;
    }
    if (note.want_average) {
        result.code = "HELD";
        result.averaged = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.averaged = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
