// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnograd.h>

#include <string>

namespace modelnet {

SwarmNotNoGradResult SwarmNoteNotNoGrad(const SwarmNotNoGrad& note, std::string& err)
{
    SwarmNotNoGradResult result;
    result.synced = false;
    result.bytes_moved = false;
    // Gradient sync has not run. This note moves no bytes.
    if (note.step_id.empty()) {
        result.code = "STEP";
        result.synced = false;
        result.bytes_moved = false;
        err = "STEP";
        return result;
    }
    if (note.want_sync) {
        result.code = "NOT_SYNCED";
        result.synced = false;
        result.bytes_moved = false;
        err = "NOT_SYNCED";
        return result;
    }
    result.code = "NOTED";
    result.synced = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
