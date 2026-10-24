// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmodelon.h>

#include <string>

namespace modelnet {

SwarmNotModelOnResult SwarmNoteNotModelOn(const SwarmNotModelOn& note, std::string& err)
{
    SwarmNotModelOnResult result;
    result.disabled = false;
    // ModelNet defaults on. This note does not change a flag or launch a process.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.disabled = false;
        err = "NODE";
        return result;
    }
    if (!note.modelnet_on) {
        result.code = "DEFAULT_ON";
        result.disabled = false;
        err = "DEFAULT_ON";
        return result;
    }
    if (note.want_disable) {
        result.code = "DEFAULT_ON";
        result.disabled = false;
        err = "DEFAULT_ON";
        return result;
    }
    result.code = "NOTED";
    result.disabled = false;
    err.clear();
    return result;
}

} // namespace modelnet
