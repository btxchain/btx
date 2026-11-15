// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowflow.h>

#include <string>

namespace modelnet {

SwarmNotNoWflowResult SwarmNoteNotNoWflow(const SwarmNotNoWflow& note, std::string& err)
{
    SwarmNotNoWflowResult result;
    result.launched = false;
    result.bytes_moved = false;
    // This note launches no workflow.
    if (note.workflow_id.empty()) {
        result.code = "WORKFLOW";
        result.launched = false;
        result.bytes_moved = false;
        err = "WORKFLOW";
        return result;
    }
    if (note.want_launch) {
        result.code = "NOT_LAUNCHED";
        result.launched = false;
        result.bytes_moved = false;
        err = "NOT_LAUNCHED";
        return result;
    }
    result.code = "NOTED";
    result.launched = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
