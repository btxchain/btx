// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnometered2.h>

#include <string>

namespace modelnet {

SwarmNotNoMetered2Result SwarmNoteNotNoMetered2(const SwarmNotNoMetered2& note, std::string& err)
{
    SwarmNotNoMetered2Result result;
    result.running = false;
    result.workers = 0;
    // The governor drains workers to zero on a metered link.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.running = false;
        result.workers = 0;
        err = "NODE";
        return result;
    }
    if (note.metered) {
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
