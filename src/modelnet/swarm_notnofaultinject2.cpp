// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofaultinject2.h>

#include <string>

namespace modelnet {

SwarmNotNoFaultInject2Result SwarmNoteNotNoFaultInject2(const SwarmNotNoFaultInject2& note, std::string& err)
{
    SwarmNotNoFaultInject2Result result;
    result.injected = false;
    result.bytes_moved = false;
    // A unit note does not inject a live fault.
    if (note.fault_id.empty()) {
        result.code = "FAULT";
        result.injected = false;
        result.bytes_moved = false;
        err = "FAULT";
        return result;
    }
    if (note.want_inject) {
        result.code = "HELD";
        result.injected = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.injected = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
