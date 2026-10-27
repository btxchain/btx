// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnothermal2.h>

#include <string>

namespace modelnet {

SwarmNotNoThermal2Result SwarmNoteNotNoThermal2(const SwarmNotNoThermal2& note, std::string& err)
{
    SwarmNotNoThermal2Result result;
    result.running = false;
    result.workers = 0;
    // The governor drains workers to zero on thermal.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.running = false;
        result.workers = 0;
        err = "NODE";
        return result;
    }
    if (note.thermal) {
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
