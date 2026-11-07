// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notstale.h>

#include <string>

namespace modelnet {

SwarmNotStaleResult SwarmNoteNotStale(const SwarmNotStale& note, std::string& err)
{
    SwarmNotStaleResult result;
    result.committed = false;
    // An old coordinator with a stale epoch commits nothing.
    if (note.epoch_id.empty()) {
        result.code = "EPOCH";
        result.committed = false;
        err = "EPOCH";
        return result;
    }
    if (note.want_commit) {
        result.code = "STALE";
        result.committed = false;
        err = "STALE";
        return result;
    }
    result.code = "NOTED";
    result.committed = false;
    err.clear();
    return result;
}

} // namespace modelnet
