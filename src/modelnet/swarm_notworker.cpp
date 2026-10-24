// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notworker.h>

namespace modelnet {

SwarmNotWorkerResult SwarmNoteNotWorker(const SwarmNotWorker& note, std::string& err)
{
    SwarmNotWorkerResult result;
    result.dropped = false;
    if (note.worker_id.empty()) {
        result.code = "WORKER";
        err = "WORKER";
        return result;
    }
    if (note.want_drop) {
        result.code = "NOT_INJECTED";
        err = "NOT_INJECTED";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
