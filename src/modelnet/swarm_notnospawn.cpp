// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnospawn.h>

#include <string>

namespace modelnet {

SwarmNotNoSpawnResult SwarmNoteNotNoSpawn(const SwarmNotNoSpawn& note, std::string& err)
{
    SwarmNotNoSpawnResult result;
    result.launched = false;
    result.external = false;
    // The control plane stays inside btxd and this note launches no sidecar.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.launched = false;
        result.external = false;
        err = "NODE";
        return result;
    }
    if (note.want_exec) {
        result.code = "NOT_LAUNCHED";
        result.launched = false;
        result.external = false;
        err = "NOT_LAUNCHED";
        return result;
    }
    result.code = "NOTED";
    result.launched = false;
    result.external = false;
    err.clear();
    return result;
}

} // namespace modelnet
