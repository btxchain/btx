// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomodelon.h>

#include <string>

namespace modelnet {

SwarmNotNoModelOnResult SwarmNoteNotNoModelOn(const SwarmNotNoModelOn& note, std::string& err)
{
    SwarmNotNoModelOnResult result;
    result.disabled = false;
    result.stopped = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.disabled = false;
        result.stopped = false;
        err = "NODE";
        return result;
    }
    // ModelNet stays on by default. This note does not stop it.
    if (note.want_disable) {
        result.code = "HELD";
        result.disabled = false;
        result.stopped = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.disabled = false;
    result.stopped = false;
    err.clear();
    return result;
}

} // namespace modelnet
