// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoidleoff2.h>

#include <string>

namespace modelnet {

SwarmNotNoIdleOff2Result SwarmNoteNotNoIdleOff2(const SwarmNotNoIdleOff2& note, std::string& err)
{
    // The governor drains workers to zero when idle is off.
    SwarmNotNoIdleOff2Result result;
    result.running = false;
    result.workers = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.running = false;
        result.workers = 0;
        err = "NODE";
        return result;
    }
    // idle_off is DRAINED even when want_run is false.
    if (note.idle_off) {
        result.code = "DRAINED";
        result.running = false;
        result.workers = 0;
        err = "DRAINED";
        return result;
    }
    if (note.want_run) {
        result.code = "HELD";
        result.running = false;
        result.workers = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.running = false;
    result.workers = 0;
    err.clear();
    return result;
}

} // namespace modelnet
