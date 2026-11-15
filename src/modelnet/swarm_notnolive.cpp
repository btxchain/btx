// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolive.h>

#include <string>

namespace modelnet {

SwarmNotNoLiveResult SwarmNoteNotNoLive(const SwarmNotNoLive& note, std::string& err)
{
    SwarmNotNoLiveResult result;
    result.injected = false;
    result.bytes_moved = false;
    // A local recovery note is not a live fault injection.
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
