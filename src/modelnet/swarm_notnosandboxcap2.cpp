// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosandboxcap2.h>

#include <string>

namespace modelnet {

SwarmNotNoSandboxCap2Result SwarmNoteNotNoSandboxCap2(const SwarmNotNoSandboxCap2& note, std::string& err)
{
    SwarmNotNoSandboxCap2Result result;
    result.raised = false;
    if (note.sandbox_id.empty()) {
        result.code = "SANDBOX";
        result.raised = false;
        err = "SANDBOX";
        return result;
    }
    // A sandbox raise stays capped.
    if (note.want_raise) {
        result.code = "CAPPED";
        result.raised = false;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.raised = false;
    err.clear();
    return result;
}

} // namespace modelnet
