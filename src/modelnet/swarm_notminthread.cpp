// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notminthread.h>

#include <string>

namespace modelnet {

SwarmNotMinThreadResult SwarmNoteNotMinThread(const SwarmNotMinThread& note, std::string& err)
{
    SwarmNotMinThreadResult result;
    result.applied = false;
    result.applied_threads = 0;
    // CPU threads have a floor of 1. This note applies none.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.applied = false;
        result.applied_threads = 0;
        err = "NODE";
        return result;
    }
    // A thread count below 1 is FLOOR even when want_apply is false.
    if (note.thread_count < 1) {
        result.code = "FLOOR";
        result.applied = false;
        result.applied_threads = 0;
        err = "FLOOR";
        return result;
    }
    // This note applies none.
    if (note.want_apply) {
        result.code = "HELD";
        result.applied = false;
        result.applied_threads = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.applied = false;
    result.applied_threads = 0;
    err.clear();
    return result;
}

} // namespace modelnet
