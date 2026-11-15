// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsandbox.h>

namespace modelnet {

SwarmNotSandboxResult SwarmNoteNotSandbox(const SwarmNotSandbox& note, std::string& err)
{
    SwarmNotSandboxResult result;
    result.launched = false;
    result.restricted = false;
    // This note does not start a child, torchrun, NCCL, FSDP, or a sandbox.
    if (note.executor_id.empty()) {
        result.code = "EXECUTOR";
        result.launched = false;
        result.restricted = false;
        err = "EXECUTOR";
        return result;
    }
    if (note.want_launch) {
        result.code = "SANDBOX_ABSENT";
        result.launched = false;
        result.restricted = false;
        err = "SANDBOX_ABSENT";
        return result;
    }
    result.code = "NOTED";
    result.launched = false;
    result.restricted = false;
    err.clear();
    return result;
}

} // namespace modelnet
