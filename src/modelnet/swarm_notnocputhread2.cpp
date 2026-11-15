// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocputhread2.h>

#include <string>

namespace modelnet {

SwarmNotNoCpuThread2Result SwarmNoteNotNoCpuThread2(const SwarmNotNoCpuThread2& note, std::string& err)
{
    // CPU threads stay capped at 64.
    SwarmNotNoCpuThread2Result result;
    result.raised = false;
    result.threads = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.raised = false;
        result.threads = 0;
        err = "NODE";
        return result;
    }
    if (note.requested > 64) {
        result.code = "CAPPED";
        result.raised = false;
        result.threads = 0;
        err = "CAPPED";
        return result;
    }
    if (note.want_raise) {
        result.code = "CAPPED";
        result.raised = false;
        result.threads = 0;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.raised = false;
    result.threads = 0;
    err.clear();
    return result;
}

} // namespace modelnet
