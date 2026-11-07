// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcapped.h>

namespace modelnet {

SwarmNotCappedResult SwarmNoteNotCapped(const SwarmNotCapped& note, std::string& err)
{
    // This note does not start training. A thread count above 64 is not applied.
    SwarmNotCappedResult result;
    result.training = false;
    result.applied_threads = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        err = "NODE";
        return result;
    }
    if (note.thread_count > 64 || note.want_train) {
        result.code = "CAPPED";
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
