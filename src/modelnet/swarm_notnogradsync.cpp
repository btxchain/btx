// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogradsync.h>

#include <string>

namespace modelnet {

SwarmNotNoGradSyncResult SwarmNoteNotNoGradSync(const SwarmNotNoGradSync& note, std::string& err)
{
    SwarmNotNoGradSyncResult result;
    result.synced = false;
    result.gpu = false;
    // A gradient-sync request does not run and does not mark a GPU pass.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.synced = false;
        result.gpu = false;
        err = "RUN";
        return result;
    }
    if (note.want_sync) {
        result.code = "NOT_RUN";
        result.synced = false;
        result.gpu = false;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.synced = false;
    result.gpu = false;
    err.clear();
    return result;
}

} // namespace modelnet
