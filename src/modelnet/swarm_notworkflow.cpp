// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notworkflow.h>

namespace modelnet {

SwarmNotWorkflowResult SwarmNoteNotWorkflow(const SwarmNotWorkflow& note, std::string& err)
{
    // The workflow has not been run.
    SwarmNotWorkflowResult result;
    if (note.workflow_id.empty()) {
        result.code = "TASK";
        result.completed = false;
        result.passed = false;
        err = "TASK";
        return result;
    }
    if (note.want_complete) {
        result.code = "NOT_RUN";
        result.completed = false;
        result.passed = false;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.completed = false;
    result.passed = false;
    err.clear();
    return result;
}

} // namespace modelnet
