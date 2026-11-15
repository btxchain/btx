// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocap1.h>

namespace modelnet {

SwarmNotNoCap1Result SwarmNoteNotNoCap1(const SwarmNotNoCap1& note, std::string& err)
{
    // CPU threads are at least 1, and this note applies nothing.
    SwarmNotNoCap1Result result;
    result.applied = false;
    result.threads = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.applied = false;
        result.threads = 0;
        err = "NODE";
        return result;
    }
    // A thread count below 1 is CAPPED even when want_apply is false.
    if (note.thread_count < 1) {
        result.code = "CAPPED";
        result.applied = false;
        result.threads = 0;
        err = "CAPPED";
        return result;
    }
    if (note.want_apply) {
        result.code = "CAPPED";
        result.applied = false;
        result.threads = 0;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.applied = false;
    result.threads = 0;
    err.clear();
    return result;
}

} // namespace modelnet
