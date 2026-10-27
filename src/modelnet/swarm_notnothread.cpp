// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnothread.h>

namespace modelnet {

SwarmNotNoThreadResult SwarmNoteNotNoThread(const SwarmNotNoThread& note, std::string& err)
{
    // CPU threads above 64 are capped, and this note trains nothing.
    SwarmNotNoThreadResult result;
    result.training = false;
    result.applied_threads = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.training = false;
        result.applied_threads = 0;
        err = "NODE";
        return result;
    }
    // A thread count above 64 is CAPPED even when want_train is false.
    if (note.thread_count > 64) {
        result.code = "CAPPED";
        result.training = false;
        result.applied_threads = 0;
        err = "CAPPED";
        return result;
    }
    if (note.want_train) {
        result.code = "CAPPED";
        result.training = false;
        result.applied_threads = 0;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.training = false;
    result.applied_threads = 0;
    err.clear();
    return result;
}

} // namespace modelnet
