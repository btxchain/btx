// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnostale.h>

#include <string>

namespace modelnet {

SwarmNotNoStaleResult SwarmNoteNotNoStale(const SwarmNotNoStale& note, std::string& err)
{
    SwarmNotNoStaleResult result;
    result.committed = false;
    result.broadcast = false;
    // A stale leader does not commit.
    if (note.leader_id.empty()) {
        result.code = "LEADER";
        result.committed = false;
        result.broadcast = false;
        err = "LEADER";
        return result;
    }
    if (note.stale) {
        result.code = "STALE";
        result.committed = false;
        result.broadcast = false;
        err = "STALE";
        return result;
    }
    if (note.want_commit) {
        result.code = "STALE";
        result.committed = false;
        result.broadcast = false;
        err = "STALE";
        return result;
    }
    result.code = "NOTED";
    result.committed = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
