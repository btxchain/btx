// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notgovernor.h>

#include <string>

namespace modelnet {

SwarmNotGovernorResult SwarmNoteNotGovernor(const SwarmNotGovernor& note, std::string& err)
{
    SwarmNotGovernorResult result;
    result.drained = false;
    result.workers = 0;
    // This note records the drain rule and does not stop a process.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.drained = false;
        result.workers = 0;
        err = "NODE";
        return result;
    }
    if (note.idle_off || note.battery || note.thermal || note.metered) {
        result.code = "DRAIN";
        result.drained = false;
        result.workers = 0;
        err = "DRAIN";
        return result;
    }
    if (note.want_keep) {
        result.code = "DRAIN";
        result.drained = false;
        result.workers = 0;
        err = "DRAIN";
        return result;
    }
    result.code = "NOTED";
    result.drained = false;
    result.workers = 0;
    err.clear();
    return result;
}

} // namespace modelnet
