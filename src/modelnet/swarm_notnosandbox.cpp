// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosandbox.h>

#include <string>

namespace modelnet {

SwarmNotNoSandboxResult SwarmNoteNotNoSandbox(const SwarmNotNoSandbox& note, std::string& err)
{
    SwarmNotNoSandboxResult result;
    result.raised = false;
    result.bytes = 0;
    if (note.job_id.empty()) {
        result.code = "JOB";
        result.raised = false;
        result.bytes = 0;
        err = "JOB";
        return result;
    }
    // A sandbox raise request stays capped and moves no bytes.
    if (note.want_raise) {
        result.code = "CAPPED";
        result.raised = false;
        result.bytes = 0;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.raised = false;
    result.bytes = 0;
    err.clear();
    return result;
}

} // namespace modelnet
