// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nosidecar.h>

namespace modelnet {

SwarmNoSidecarResult SwarmNoteNoSidecar(const SwarmNoSidecar& note, std::string& err)
{
    SwarmNoSidecarResult result;
    result.launched = false;
    if (note.node_id.empty()) {
        result.code = "SIDECAR";
        result.launched = false;
        err = "SIDECAR";
        return result;
    }
    // btxd does not exec btx-swarmd or btx-paynetd.
    if (note.want_exec) {
        result.code = "NOT_LAUNCHED";
        result.launched = false;
        err = "NOT_LAUNCHED";
        return result;
    }
    result.code = "NOTED";
    result.launched = false;
    err.clear();
    return result;
}

} // namespace modelnet
