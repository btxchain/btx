// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogradsync2.h>

#include <string>

namespace modelnet {

SwarmNotNoGradSync2Result SwarmNoteNotNoGradSync2(const SwarmNotNoGradSync2& note, std::string& err)
{
    SwarmNotNoGradSync2Result result;
    result.synced = false;
    result.bytes_moved = false;
    // A gradient-sync request does not run.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.synced = false;
        result.bytes_moved = false;
        err = "RUN";
        return result;
    }
    if (note.want_sync) {
        result.code = "NOT_RUN";
        result.synced = false;
        result.bytes_moved = false;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.synced = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
