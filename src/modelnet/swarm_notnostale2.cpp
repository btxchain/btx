// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnostale2.h>

#include <string>

namespace modelnet {

SwarmNotNoStale2Result SwarmNoteNotNoStale2(const SwarmNotNoStale2& note, std::string& err)
{
    SwarmNotNoStale2Result result;
    result.admitted = false;
    result.bytes_moved = false;
    // A stale island update is not admitted.
    if (note.island_id.empty()) {
        result.code = "ISLAND";
        result.admitted = false;
        result.bytes_moved = false;
        err = "ISLAND";
        return result;
    }
    if (note.stale) {
        result.code = "NOT_ADMITTED";
        result.admitted = false;
        result.bytes_moved = false;
        err = "NOT_ADMITTED";
        return result;
    }
    if (note.want_admit) {
        result.code = "HELD";
        result.admitted = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.admitted = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
