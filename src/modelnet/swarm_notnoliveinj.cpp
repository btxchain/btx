// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoliveinj.h>

#include <string>

namespace modelnet {

SwarmNotNoLiveInjResult SwarmNoteNotNoLiveInj(const SwarmNotNoLiveInj& note, std::string& err)
{
    SwarmNotNoLiveInjResult result;
    result.injected = false;
    result.bytes_moved = false;
    // A unit note injects no live fault and moves no bytes.
    if (note.fault_id.empty()) {
        result.code = "FAULT";
        result.injected = false;
        result.bytes_moved = false;
        err = "FAULT";
        return result;
    }
    if (note.want_inject) {
        result.code = "NOT_INJECTED";
        result.injected = false;
        result.bytes_moved = false;
        err = "NOT_INJECTED";
        return result;
    }
    result.code = "NOTED";
    result.injected = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
