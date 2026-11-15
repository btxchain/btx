// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnothreads64.h>

#include <string>

namespace modelnet {

SwarmNotNoThreads64Result SwarmNoteNotNoThreads64(const SwarmNotNoThreads64& note, std::string& err)
{
    // A unit note does not raise the CPU thread cap above 64.
    SwarmNotNoThreads64Result result;
    result.raised = false;
    result.threads = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.raised = false;
        result.threads = 0;
        err = "NODE";
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
