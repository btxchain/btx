// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosandbox2.h>

#include <string>

namespace modelnet {

SwarmNotNoSandbox2Result SwarmNoteNotNoSandbox2(const SwarmNotNoSandbox2& note, std::string& err)
{
    SwarmNotNoSandbox2Result result;
    result.raised = false;
    result.cap = 0;
    if (note.sandbox_id.empty()) {
        result.code = "SANDBOX";
        result.raised = false;
        result.cap = 0;
        err = "SANDBOX";
        return result;
    }
    // A sandbox raise stays capped.
    if (note.want_raise) {
        result.code = "CAPPED";
        result.raised = false;
        result.cap = 0;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.raised = false;
    result.cap = 0;
    err.clear();
    return result;
}

} // namespace modelnet
