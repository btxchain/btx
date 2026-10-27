// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsidecar2.h>

namespace modelnet {

SwarmNotSidecar2Result SwarmNoteNotSidecar2(const SwarmNotSidecar2& note, std::string& err)
{
    SwarmNotSidecar2Result result;
    result.external = false;
    result.launched = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.external = false;
        result.launched = false;
        err = "NODE";
        return result;
    }
    // The control plane stays inside btxd.
    if (note.want_external) {
        result.code = "INSIDE";
        result.external = false;
        result.launched = false;
        err = "INSIDE";
        return result;
    }
    result.code = "NOTED";
    result.external = false;
    result.launched = false;
    err.clear();
    return result;
}

} // namespace modelnet
